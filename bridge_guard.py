#!/usr/bin/env python3
"""bridge-guard — сторож мостов для Remnawave.

Раз в минуту проверяет каждый мост НАСТОЯЩИМ клиентом (xray + VLESS/Reality → выход в
интернет), а не TCP-коннектом на порт. Мёртвый мост уходит из DNS-пула и/или из хостов
подписки на живой; ожил — возвращается. О каждом переходе — сообщение в Telegram.

  bridge-guard --config /etc/bridge-guard/config.json            # обычный прогон (таймер)
  bridge-guard --config ... --dry-run                            # ничего не менять, только решения
  bridge-guard --config ... --dry-run --fake-dead RF-2           # репетиция отказа моста RF-2
  bridge-guard --config ... --status                             # что сторож думает о мостах сейчас

Коды выхода: 0 — все мосты живы, 1 — есть мёртвые, 2 — ошибка конфигурации/панели.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.0.0"

DEFAULT_THRESHOLDS = {"fail_n": 3, "ok_n": 3, "max_dead": 1}
DEFAULT_PROBE = {
    "port": 2053,
    "sni": "www.cloudflare.com",
    "fingerprint": "firefox",
    "flow": "xtls-rprx-vision",
    "timeout": 12,
    "port_base": 3140,
    "urls": ["https://1.1.1.1/cdn-cgi/trace", "https://api.ipify.org"],
}
DEFAULT_PATHS = {
    "xray": "/opt/bridge-guard/xray",
    "state": "/var/lib/bridge-guard/state.json",
    "backups": "/var/lib/bridge-guard/backups",
}


# ──────────────────────────── конфигурация ────────────────────────────

def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["thresholds"] = {**DEFAULT_THRESHOLDS, **cfg.get("thresholds", {})}
    cfg["probe"] = {**DEFAULT_PROBE, **cfg.get("probe", {})}
    cfg["paths"] = {**DEFAULT_PATHS, **cfg.get("paths", {})}
    cfg.setdefault("failover", {})
    cfg.setdefault("telegram", {})
    problems = []
    if not cfg.get("bridges"):
        problems.append("bridges: список мостов пуст")
    for b in cfg.get("bridges", []):
        if not b.get("name") or not b.get("ip"):
            problems.append(f"bridges: у моста нужны name и ip: {b}")
    checks = {  # формат, чтобы не уйти в бой с текстом-заглушкой из примера
        "uuid": (r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", "vlessUuid вида 8-4-4-4-12"),
        "public_key": (r"^[A-Za-z0-9_-]{43}$", "публичный ключ Reality (43 символа base64url)"),
        "short_id": (r"^[0-9a-fA-F]{0,16}$", "shortId — до 16 hex-символов"),
    }
    for key, (pattern, hint) in checks.items():
        val = str(cfg["probe"].get(key) or "")
        if not val or not re.match(pattern, val):
            problems.append(f"probe.{key}: не задан или не похож на {hint} (docs/panel-setup.md)")
    fo = cfg["failover"]
    if not fo.get("dns") and not fo.get("hosts"):
        problems.append("failover: не задан ни dns, ни hosts — сторожу нечего переключать")
    if fo.get("hosts") and not (cfg.get("panel", {}).get("url") and cfg.get("panel", {}).get("token")):
        problems.append("failover.hosts требует panel.url и panel.token")
    if fo.get("dns"):
        for key in ("zone", "name", "token_file"):
            if not fo["dns"].get(key):
                problems.append(f"failover.dns.{key}: не задан")
    if not os.path.exists(cfg["paths"]["xray"]):
        problems.append(f"paths.xray: нет файла {cfg['paths']['xray']} (scripts/install.sh скачает Xray-core)")
    if problems:
        print("Ошибки конфигурации:\n  - " + "\n  - ".join(problems), file=sys.stderr)
        sys.exit(2)
    return cfg


# ──────────────────────────── внешние сервисы ─────────────────────────

class Panel:
    """Тонкий клиент Remnawave API — только хосты подписки."""

    def __init__(self, url, token):
        self.url, self.token = url.rstrip("/"), token

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            self.url + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=40) as r:
            payload = json.loads(r.read().decode())
        return payload.get("response", payload)

    def hosts(self):
        data = self.call("GET", "/api/hosts")
        return data.get("hosts", data) if isinstance(data, dict) else data

    def set_host_address(self, uuid, address):
        return self.call("PATCH", "/api/hosts", {"uuid": uuid, "address": address})


class Cloudflare:
    """A-записи одного имени: убрать/вернуть адрес. Токен — только DNS:Edit на одну зону."""

    def __init__(self, token_file, zone, name, ttl=60):
        with open(token_file) as f:
            self.token = f.read().strip()
        self.zone_name, self.name, self.ttl = zone, name, ttl
        self._zone_id = None

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4" + path, method=method,
            data=json.dumps(body).encode() if body else None,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def zone_id(self):
        if not self._zone_id:
            res = self.call("GET", f"/zones?name={self.zone_name}")["result"]
            if not res:
                raise RuntimeError(f"зона {self.zone_name} не найдена (проверьте токен и имя зоны)")
            self._zone_id = res[0]["id"]
        return self._zone_id

    def records(self):
        return self.call("GET", f"/zones/{self.zone_id()}/dns_records?type=A&name={self.name}&per_page=100")["result"]

    def remove(self, ip):
        removed = 0
        for r in self.records():
            if r["content"] == ip:
                self.call("DELETE", f"/zones/{self.zone_id()}/dns_records/{r['id']}")
                removed += 1
        return removed

    def add(self, ip):
        if any(r["content"] == ip for r in self.records()):
            return False
        self.call("POST", f"/zones/{self.zone_id()}/dns_records",
                  {"type": "A", "name": self.name, "content": ip, "ttl": self.ttl, "proxied": False})
        return True


def telegram_send(tg, text, quiet=False):
    """Сообщение админу. Если задан proxy — сначала через него (на российских серверах
    api.telegram.org часто недоступен напрямую), потом напрямую; 5 попыток."""
    if quiet or not tg.get("bot_token") or not tg.get("chat_id"):
        print("  telegram: тихо (quiet или не настроен)")
        return False
    data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": "🌉 Сторож мостов\n" + text,
                                   "disable_web_page_preview": "true"}).encode()
    proxy = tg.get("proxy") or None
    plan = [proxy, None, proxy, None, None] if proxy else [None] * 4
    last = None
    for p in plan:
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": p} if p else {}))
            opener.open(urllib.request.Request(f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage",
                                               data=data), timeout=20).read()
            print("  telegram: отправлено")
            return True
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2)
    print("  telegram НЕ отправился:", str(last)[:100])
    return False


# ──────────────────────────── проба настоящим клиентом ────────────────

def probe_bridge(cfg, ip, local_port):
    """True, если через мост ip клиент реально выходит в интернет (получен внешний IPv4)."""
    pr = cfg["probe"]
    xcfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": local_port, "protocol": "http", "settings": {}}],
        "outbounds": [{
            "tag": "out", "protocol": "vless",
            "settings": {"vnext": [{"address": ip, "port": pr["port"],
                                    "users": [{"id": pr["uuid"], "encryption": "none", "flow": pr["flow"]}]}]},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"serverName": pr["sni"], "fingerprint": pr["fingerprint"],
                                                   "publicKey": pr["public_key"], "shortId": pr["short_id"]}}}],
    }
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(xcfg, tmp)
    tmp.close()
    proc = subprocess.Popen([cfg["paths"]["xray"], "run", "-config", tmp.name],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{local_port}"}))
        for url in pr["urls"]:
            try:
                body = opener.open(url, timeout=pr["timeout"]).read().decode(errors="replace")
                if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", body):
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False
    finally:
        proc.kill()
        proc.wait()
        os.unlink(tmp.name)


# ──────────────────────────── переключения ────────────────────────────

def backup_hosts(cfg, hosts):
    os.makedirs(cfg["paths"]["backups"], exist_ok=True)
    path = os.path.join(cfg["paths"]["backups"], f"hosts.{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)
    return path


def hosts_switch(cfg, panel, state, to_ip, dry):
    """Хосты подписки с адресом match_address → to_ip. Возврат: to_ip=None."""
    match = cfg["failover"]["hosts"]["match_address"]
    hosts = panel.hosts()
    if to_ip:
        todo = [h for h in hosts if h.get("address") == match]
        if not todo:
            return f"хосты: с адресом {match} не найдено — переключать нечего"
        if dry:
            return f"[dry-run] хостов перевёл бы на {to_ip}: {len(todo)}"
        bpath = backup_hosts(cfg, hosts)
        for h in todo:
            panel.set_host_address(h["uuid"], to_ip)
        state["switched"] = {"to": to_ip, "hosts": [h["uuid"] for h in todo],
                             "at": time.strftime("%Y-%m-%d %H:%M:%S"), "backup": bpath}
        return f"хостов переведено на {to_ip}: {len(todo)} (бэкап {os.path.basename(bpath)})"
    sw = state.get("switched") or {}
    todo = [h for h in hosts if h["uuid"] in sw.get("hosts", []) and h.get("address") == sw.get("to")]
    if dry:
        return f"[dry-run] хостов вернул бы на {match}: {len(todo)}"
    backup_hosts(cfg, hosts)
    for h in todo:
        panel.set_host_address(h["uuid"], match)
    state["switched"] = None
    return f"хостов возвращено на {match}: {len(todo)}"


def dns_change(cfg, dns_client, ip, present, alive_ips, dry):
    """present=False — убрать A-запись мёртвого моста, True — вернуть. Бережём min_pool."""
    if not dns_client:
        return None
    d = cfg["failover"]["dns"]
    try:
        recs = dns_client.records()
        pool = {r["content"] for r in recs}
        if not present:
            if ip not in pool:
                return f"DNS: {ip} и так нет в {d['name']}"
            if len(pool) - 1 < d.get("min_pool", 1):
                return f"DNS: НЕ убираю {ip} — в пуле осталось бы {len(pool) - 1} < min_pool={d.get('min_pool', 1)}"
            if dry:
                return f"[dry-run] DNS: убрал бы A {d['name']} → {ip}"
            dns_client.remove(ip)
            return f"DNS: A {d['name']} → {ip} убрана"
        if ip in pool:
            return f"DNS: {ip} уже в {d['name']}"
        if dry:
            return f"[dry-run] DNS: вернул бы A {d['name']} → {ip}"
        dns_client.add(ip)
        return f"DNS: A {d['name']} → {ip} возвращена"
    except Exception as e:  # noqa: BLE001
        return f"DNS: ошибка — {str(e)[:120]}"


# ──────────────────────────── основной прогон ─────────────────────────

def load_state(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {"bridges": {}, "switched": None, "frozen": False}


def save_state(path, state):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def show_status(cfg, state):
    print(f"bridge-guard {VERSION} — состояние ({cfg['paths']['state']})")
    for b in cfg["bridges"]:
        s = state["bridges"].get(b["name"], {"fails": 0, "oks": 0, "dead": False})
        print(f"  {b['name']:<16} {b['ip']:<16} {'МЁРТВ' if s['dead'] else 'жив':<6} провалов подряд {s['fails']}, успехов {s['oks']}")
    sw = state.get("switched")
    print("  хосты:", f"переведены на {sw['to']} в {sw['at']}" if sw else "на своём имени")
    print("  заморозка:", "ДА — слишком много мостов упало разом, автодействия остановлены" if state.get("frozen") else "нет")


def run(cfg, dry=False, quiet=False, fake_dead=()):
    th, bridges = cfg["thresholds"], cfg["bridges"]
    state = load_state(cfg["paths"]["state"])
    st = state["bridges"]
    names = [b["name"] for b in bridges]
    ip_of = {b["name"]: b["ip"] for b in bridges}
    for gone in [n for n in st if n not in names]:
        del st[gone]

    # 1. пробы — параллельно, у каждого моста свой локальный порт
    def one(i_b):
        i, b = i_b
        if b["name"] in fake_dead:
            return b["name"], False
        return b["name"], probe_bridge(cfg, b["ip"], cfg["probe"]["port_base"] + i)

    with ThreadPoolExecutor(max_workers=min(8, len(bridges))) as ex:
        results = dict(ex.map(one, enumerate(bridges)))

    for name in names:
        ok = results[name]
        s = st.setdefault(name, {"fails": 0, "oks": 0, "dead": False})
        s["fails"], s["oks"] = (0, s["oks"] + 1) if ok else (s["fails"] + 1, 0)
        if name in fake_dead:
            s["fails"] = max(s["fails"], th["fail_n"])   # репетиция: «мёртв» сразу, без ожидания fail_n
        print(f"  {name} {ip_of[name]}: {'ок' if ok else 'ПРОВАЛ'} (провалов подряд {s['fails']}, успехов {s['oks']}, "
              f"{'мёртв' if s['dead'] else 'жив'})")

    # 2. события с гистерезисом
    events = []
    for name in names:
        s = st[name]
        if not s["dead"] and s["fails"] >= th["fail_n"]:
            s["dead"] = True
            events.append(("died", name))
        elif s["dead"] and s["oks"] >= th["ok_n"]:
            s["dead"] = False
            events.append(("revived", name))
    dead = [n for n in names if st[n]["dead"]]
    alive = [n for n in names if not st[n]["dead"]]

    # 3. защита: слишком много мёртвых разом = скорее сеть/сторож, чем мосты
    newly_dead = [n for ev, n in events if ev == "died"]
    if len(dead) > th["max_dead"] and newly_dead:
        if not state.get("frozen"):
            state["frozen"] = True
            msg = (f"🟠 Мёртвых мостов сразу {len(dead)} ({', '.join(dead)}) — больше max_dead={th['max_dead']}. "
                   f"Похоже на проблему сети или самого сторожа, а не мостов. Автодействия ОСТАНОВЛЕНЫ, "
                   f"DNS и хосты не трогаю. Проверьте сторож вручную (bridge-guard --status).")
            print("  " + msg)
            telegram_send(cfg["telegram"], msg, quiet)
        if not dry:
            save_state(cfg["paths"]["state"], state)
        return 1
    if state.get("frozen") and len(dead) <= th["max_dead"]:
        state["frozen"] = False
        telegram_send(cfg["telegram"], "🟢 Мостов в норме достаточно — автодействия снова включены.", quiet)
        # пока стояла заморозка, «умершие» не обрабатывались — доделываем сейчас
        events += [("died", n) for n in dead if ("died", n) not in events]

    # 4. действия
    fo = cfg["failover"]
    panel = Panel(cfg["panel"]["url"], cfg["panel"]["token"]) if fo.get("hosts") else None
    dns_client = None
    if fo.get("dns"):
        try:
            dns_client = Cloudflare(fo["dns"]["token_file"], fo["dns"]["zone"], fo["dns"]["name"], fo["dns"].get("ttl", 60))
        except Exception as e:  # noqa: BLE001
            print("  DNS отключён:", str(e)[:100])
    alive_ips = [ip_of[n] for n in alive]

    for ev, name in events:
        ip = ip_of[name]
        if ev == "died":
            lines = [f"🔴 {name} ({ip}) не проходит проверку {th['fail_n']} раз подряд — клиент через него не выходит в сеть."]
            if alive:
                lines.append(dns_change(cfg, dns_client, ip, False, alive_ips, dry))
                if panel and not state.get("switched"):
                    lines.append(hosts_switch(cfg, panel, state, alive_ips[0], dry))
                lines.append(f"Живые мосты: {', '.join(f'{n} ({ip_of[n]})' for n in alive)}. "
                             f"Новые подключения уйдут на них сразу, остальные — при автообновлении подписки.")
            else:
                lines.append("🔴🔴 ЖИВЫХ МОСТОВ НЕТ. Переключать некуда — нужен живой мост.")
        else:
            lines = [f"🟢 {name} ({ip}) снова проходит проверку {th['ok_n']} раз подряд."]
            lines.append(dns_change(cfg, dns_client, ip, True, alive_ips, dry))
            if panel and state.get("switched"):
                lines.append(hosts_switch(cfg, panel, state, None, dry) if not dead
                             else f"хосты остаются на {state['switched']['to']} — ещё есть мёртвые мосты: {', '.join(dead)}")
        lines = [ln for ln in lines if ln]
        print("\n".join("  " + ln for ln in lines))
        telegram_send(cfg["telegram"], "\n".join(lines), quiet)

    if not dry:
        save_state(cfg["paths"]["state"], state)
    sw = state.get("switched")
    print(f"  итог: живы {alive or '—'}, мертвы {dead or '—'}, хосты {'переведены на ' + sw['to'] if sw else 'на своём имени'}")
    return 1 if dead else 0


def main():
    ap = argparse.ArgumentParser(description="bridge-guard — сторож мостов Remnawave (проверка настоящим клиентом)")
    ap.add_argument("--config", default=os.environ.get("BRIDGE_GUARD_CONFIG", "/etc/bridge-guard/config.json"))
    ap.add_argument("--dry-run", action="store_true", help="ничего не менять (DNS, хосты, состояние), только решения")
    ap.add_argument("--quiet", action="store_true", help="без Telegram")
    ap.add_argument("--fake-dead", default="", help="считать мосты мёртвыми сразу (имена через запятую) — репетиция отказа")
    ap.add_argument("--status", action="store_true", help="показать состояние и выйти")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args()
    cfg = load_config(a.config)
    if a.status:
        show_status(cfg, load_state(cfg["paths"]["state"]))
        return 0
    fake = {x.strip() for x in a.fake_dead.split(",") if x.strip()}
    unknown = fake - {b["name"] for b in cfg["bridges"]}
    if unknown:
        print(f"--fake-dead: нет таких мостов в конфиге: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    if a.dry_run:
        print("  [dry-run] изменения не применяются")
    elif fake:
        print("  ВНИМАНИЕ: --fake-dead без --dry-run переключит DNS и хосты по-настоящему")
    return run(cfg, dry=a.dry_run, quiet=a.quiet or a.dry_run, fake_dead=fake)


if __name__ == "__main__":
    sys.exit(main())
