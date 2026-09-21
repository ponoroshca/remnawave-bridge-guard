#!/usr/bin/env python3
"""lanes-probe — пройти каждый режим подписки через мост как настоящий клиент.

Для каждого VLESS-инбаунда профиля моста собирает клиента так же, как ссылка подписки
(транспорт и безопасность из профиля, sni/отпечаток/путь из хоста), и через него
спрашивает внешний IP, меряет отклик и скорость скачивания. Это ответ на вопрос
«у клиентов всё работает?» цифрами, а не «панель говорит, что ноды на связи».

  lanes-probe --bridge RF-1                # мост по имени из конфига сторожа
  lanes-probe --bridge 203.0.113.10        # или по IP (профиль возьмётся из панели)
  lanes-probe --bridge RF-1 --no-speed     # без замера скорости (быстрее)
  lanes-probe --bridge RF-1 --speed-url URL --speed-seconds 8

Служебный пользователь (probe.uuid) должен быть в сквадах проверяемых инбаундов —
иначе режим покажет «нет выхода», хотя у клиентов он может работать.
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bridge_guard import Panel, build_outbound, inbound_client_params, is_ip, read_config  # noqa: E402

VERSION = "1.2.0"


def fetch(proxy, url, timeout, max_seconds=None, max_bytes=None):
    """(тело или None, секунд до первого байта, скачано байт, секунд всего)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    t0 = time.time()
    try:
        resp = opener.open(url, timeout=timeout)
    except Exception:  # noqa: BLE001
        return None, 0.0, 0, time.time() - t0
    first = time.time() - t0
    total, body = 0, b""
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
    ap.add_argument("--bridge", required=True, help="имя моста из конфига или его IP")
    ap.add_argument("--port-base", type=int, default=3150)
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument("--no-speed", action="store_true")
    ap.add_argument("--speed-url", default="https://fsn1-speed.hetzner.com/1GB.bin")
    ap.add_argument("--speed-seconds", type=float, default=6)
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args()

    cfg = read_config(a.config)
    panel_cfg, probe = cfg.get("panel") or {}, cfg.get("probe") or {}
    xray = cfg["paths"]["xray"]
    if not (panel_cfg.get("url") and panel_cfg.get("token") and probe.get("uuid")):
        print("нужны panel.url, panel.token и probe.uuid в конфиге сторожа (bridge-guard setup)", file=sys.stderr)
        return 2
    panel = Panel(panel_cfg["url"], panel_cfg["token"])
    nodes = panel.nodes()
    node = next((n for n in nodes if a.bridge in (n.get("name"), n.get("address"))), None)
    if not node:
        print(f"нода «{a.bridge}» не найдена в панели (имя или IP)", file=sys.stderr)
        return 2
    ip = node.get("address")
    if not is_ip(ip or ""):
        print(f"у ноды {node.get('name')} адрес не IP: {ip}", file=sys.stderr)
        return 2
    prof = next((p for p in panel.profiles() if p["uuid"] == (node.get("configProfile") or {}).get("activeConfigProfileUuid")), None)
    if not prof:
        print("у ноды нет активного профиля", file=sys.stderr)
        return 2
    hosts = panel.hosts()
    remark = {}
    for h in hosts:
        ib = h.get("inbound") or {}
        if ib.get("configProfileUuid") == prof["uuid"] and not h.get("isDisabled"):
            remark.setdefault(ib.get("configProfileInboundUuid"), h.get("remark"))

    lanes = []
    for i, ib in enumerate(sorted(prof.get("inbounds") or [], key=lambda x: x.get("port") or 0)):
        pr = inbound_client_params(prof, ib, hosts, xray, probe)
        if not pr or not pr.get("port"):
            continue
        pr["uuid"] = probe["uuid"]
        lanes.append({"tag": ib["tag"], "port": pr["port"], "lport": a.port_base + i, "pr": pr,
                      "name": remark.get(ib.get("uuid")) or ib["tag"]})
    if not lanes:
        print("в профиле нет VLESS-инбаундов", file=sys.stderr)
        return 2

    xcfg = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [], "routing": {"rules": []}}
    for ln in lanes:
        xcfg["inbounds"].append({"tag": f"in-{ln['port']}", "listen": "127.0.0.1", "port": ln["lport"], "protocol": "http", "settings": {}})
        xcfg["outbounds"].append(build_outbound(ip, ln["pr"], tag=f"out-{ln['port']}"))
        xcfg["routing"]["rules"].append({"type": "field", "inboundTag": [f"in-{ln['port']}"], "outboundTag": f"out-{ln['port']}"})
    cfg_path = f"/tmp/lanes-probe.{os.getpid()}.json"
    with open(cfg_path, "w") as f:
        json.dump(xcfg, f)
    proc = subprocess.Popen([xray, "run", "-config", cfg_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)
    if proc.poll() is not None:
        print("xray не стартовал:", proc.stdout.read().decode()[-500:], file=sys.stderr)
        os.unlink(cfg_path)
        return 2

    print(f"══ {node.get('name')} {ip} (профиль {prof['name']}) — как клиент ({time.strftime('%H:%M:%S')}) ══")
    bad = 0
    try:
        for ln in lanes:
            proxy = f"http://127.0.0.1:{ln['lport']}"
            exit_ip, ok, lat = "", False, 0.0
            for url in ("https://api.ipify.org", "https://1.1.1.1/cdn-cgi/trace"):
                body, first, _, _ = fetch(proxy, url, a.timeout, max_bytes=2048)
                text = (body or b"").decode(errors="replace")
                m = re.search(r"^ip=(\S+)$", text, re.M) or re.fullmatch(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s*", text)
                if m:
                    exit_ip, ok, lat = m.group(1), True, first
                    break
            kind = f"{ln['pr']['security']}/{ln['pr']['network']}"
            if not ok:
                bad += 1
                print(f"  :{ln['port']} {ln['name'][:28]:<28} {kind:<13} 🔴 нет выхода в интернет")
                continue
            line = f"  :{ln['port']} {ln['name'][:28]:<28} {kind:<13} ✅ выход {exit_ip:<16} отклик {lat * 1000:.0f} мс"
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
