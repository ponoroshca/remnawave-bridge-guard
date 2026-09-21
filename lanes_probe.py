#!/usr/bin/env python3
"""lanes-probe — пройти каждый режим подписки через мост как настоящий клиент.

Для каждого инбаунда профиля мостов поднимает xray-клиент (VLESS + Reality, как в приложении)
и через него спрашивает внешний IP, меряет отклик и скорость скачивания. Это ответ на вопрос
«у клиентов всё работает?» цифрами, а не «панель говорит, что ноды на связи».

  lanes-probe --config /etc/bridge-guard/config.json --profile "RF-Bridge" --bridge 203.0.113.10
  lanes-probe ... --no-speed            # без замера скорости (быстрее)
  lanes-probe ... --speed-url URL       # свой файл для замера (по умолчанию — зеркало Hetzner)

Ключи Reality берутся из профиля: публичный ключ считается из приватного (`xray x25519 -i`).
Служебный пользователь — тот же, что у сторожа (probe.uuid); он должен быть в сквадах
всех проверяемых инбаундов, иначе режим покажет «нет выхода».
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request

VERSION = "1.0.0"


def api(base, token, path):
    req = urllib.request.Request(base.rstrip("/") + path, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=30) as r:
        payload = json.loads(r.read().decode())
    return payload.get("response", payload)


def public_key(xray, private_key):
    out = subprocess.run([xray, "x25519", "-i", private_key], capture_output=True, text=True).stdout
    m = re.search(r"(?:PublicKey\)?|Public key):\s*(\S+)", out)
    return m.group(1) if m else None


def fetch(proxy, url, timeout, max_seconds=None, max_bytes=None):
    """Возвращает (тело или None, секунд до первого байта, скачано байт, секунд всего)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    t0 = time.time()
    try:
        resp = opener.open(url, timeout=timeout)
    except Exception:  # noqa: BLE001
        return None, 0.0, 0, time.time() - t0
    first = time.time() - t0
    total = 0
    body = b""
    try:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes:
                body += chunk
                if total >= max_bytes:
                    break
            if max_seconds and time.time() - t0 > max_seconds:
                break
    except Exception:  # noqa: BLE001
        pass
    return (body if max_bytes else b"x"), first, total, time.time() - t0


def main():
    ap = argparse.ArgumentParser(description="lanes-probe — все режимы подписки через мост как клиент")
    ap.add_argument("--config", default=os.environ.get("BRIDGE_GUARD_CONFIG", "/etc/bridge-guard/config.json"))
    ap.add_argument("--profile", required=True, help="имя или uuid config-профиля мостов")
    ap.add_argument("--bridge", required=True, help="IP моста, через который проверяем")
    ap.add_argument("--port-base", type=int, default=3150)
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument("--no-speed", action="store_true")
    ap.add_argument("--speed-url", default="https://fsn1-speed.hetzner.com/1GB.bin")
    ap.add_argument("--speed-seconds", type=float, default=6)
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args()

    with open(a.config, encoding="utf-8") as f:
        cfg = json.load(f)
    panel, probe = cfg.get("panel") or {}, cfg.get("probe") or {}
    xray = (cfg.get("paths") or {}).get("xray", "/opt/bridge-guard/xray")
    if not (panel.get("url") and panel.get("token") and probe.get("uuid")):
        print("нужны panel.url, panel.token и probe.uuid в конфиге сторожа", file=sys.stderr)
        return 2
    profs = api(panel["url"], panel["token"], "/api/config-profiles")
    profs = profs.get("configProfiles", profs) if isinstance(profs, dict) else profs
    prof = next((p for p in profs if a.profile in (p.get("uuid"), p.get("name"))), None)
    if not prof:
        print(f"профиль «{a.profile}» не найден", file=sys.stderr)
        return 2
    # имена режимов — из хостов подписки, привязанных именно к инбаундам этого профиля
    hosts = api(panel["url"], panel["token"], "/api/hosts")
    hosts = hosts.get("hosts", hosts) if isinstance(hosts, dict) else hosts
    remark_by_inbound = {}
    for h in hosts:
        ib = h.get("inbound") or {}
        if ib.get("configProfileUuid") == prof.get("uuid") and not h.get("isDisabled"):
            remark_by_inbound.setdefault(ib.get("configProfileInboundUuid"), h.get("remark"))
    inbound_uuid_by_tag = {i.get("tag"): i.get("uuid") for i in prof.get("inbounds", [])}

    lanes = []
    for i, ib in enumerate(sorted(prof["config"].get("inbounds", []), key=lambda x: x.get("port") or 0)):
        rs = (ib.get("streamSettings") or {}).get("realitySettings") or {}
        if not rs or not ib.get("port"):
            continue
        lanes.append({"tag": ib["tag"], "port": ib["port"], "lport": a.port_base + i,
                      "name": remark_by_inbound.get(inbound_uuid_by_tag.get(ib["tag"])) or ib["tag"],
                      "sni": (rs.get("serverNames") or [probe.get("sni", "www.cloudflare.com")])[0],
                      "sid": (rs.get("shortIds") or [""])[0], "pbk": public_key(xray, rs.get("privateKey", ""))})
    if not lanes:
        print("в профиле нет инбаундов с Reality", file=sys.stderr)
        return 2

    xcfg = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [], "routing": {"rules": []}}
    for ln in lanes:
        xcfg["inbounds"].append({"tag": f"in-{ln['port']}", "listen": "127.0.0.1", "port": ln["lport"],
                                 "protocol": "http", "settings": {}})
        xcfg["outbounds"].append({"tag": f"out-{ln['port']}", "protocol": "vless",
                                  "settings": {"vnext": [{"address": a.bridge, "port": ln["port"],
                                                          "users": [{"id": probe["uuid"], "encryption": "none",
                                                                     "flow": probe.get("flow", "xtls-rprx-vision")}]}]},
                                  "streamSettings": {"network": "tcp", "security": "reality",
                                                     "realitySettings": {"serverName": ln["sni"],
                                                                         "fingerprint": probe.get("fingerprint", "chrome"),
                                                                         "publicKey": ln["pbk"], "shortId": ln["sid"]}}})
        xcfg["routing"]["rules"].append({"type": "field", "inboundTag": [f"in-{ln['port']}"],
                                         "outboundTag": f"out-{ln['port']}"})
    cfg_path = f"/tmp/lanes-probe.{os.getpid()}.json"
    with open(cfg_path, "w") as f:
        json.dump(xcfg, f)
    proc = subprocess.Popen([xray, "run", "-config", cfg_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)
    if proc.poll() is not None:
        print("xray не стартовал:", proc.stdout.read().decode()[-500:], file=sys.stderr)
        os.unlink(cfg_path)
        return 2

    print(f"══ через {a.bridge} — как клиент ({time.strftime('%H:%M:%S')}) ══")
    bad = 0
    try:
        for ln in lanes:
            proxy = f"http://127.0.0.1:{ln['lport']}"
            ip, ok, lat = "", False, 0.0
            for url in ("https://api.ipify.org", "https://1.1.1.1/cdn-cgi/trace"):   # две попытки, разные источники
                body, first, _, _ = fetch(proxy, url, a.timeout, max_bytes=2048)
                text = (body or b"").decode(errors="replace")
                m = re.search(r"^ip=(\S+)$", text, re.M) or re.fullmatch(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s*", text)
                if m:
                    ip, ok, lat = m.group(1), True, first
                    break
            name = ln["name"]
            if not ok:
                bad += 1
                print(f"  :{ln['port']} {name[:30]:<30} 🔴 нет выхода в интернет")
                continue
            line = f"  :{ln['port']} {name[:30]:<30} ✅ выход {ip:<16} отклик {lat * 1000:.0f} мс"
            if not a.no_speed:
                _, _, nbytes, secs = fetch(proxy, a.speed_url, a.timeout, max_seconds=a.speed_seconds)
                line += f"  скачивание {(nbytes * 8 / secs / 1e6) if secs else 0:.0f} Мбит/с"
            print(line)
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()
        os.unlink(cfg_path)
    print(f"  итог: {len(lanes) - bad} из {len(lanes)} режимов работают")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
