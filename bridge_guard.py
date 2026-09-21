#!/usr/bin/env python3
"""bridge-guard — сторож мостов для Remnawave.

Раз в минуту проверяет каждый мост НАСТОЯЩИМ клиентом (xray + VLESS/Reality → выход в
интернет), а не TCP-коннектом на порт. Мёртвый мост уходит из DNS-пула и/или из хостов
подписки на живой; ожил — возвращается. О каждом переходе — сообщение в Telegram.

  bridge-guard setup                    # мастер: найдёт мосты, инбаунд, ключи, заведёт служебного
                                        # пользователя, проверит DNS и Telegram, включит таймер
  bridge-guard doctor                   # чек-лист «почему не работает»
  bridge-guard run [--dry-run] [--fake-dead RF-2]   # прогон (его запускает таймер)
  bridge-guard status                   # состояние и последние события
  bridge-guard rollback [--dry-run]     # вернуть хосты и DNS как было, сбросить состояние

Коды выхода: 0 — все мосты живы, 1 — есть мёртвые, 2 — ошибка конфигурации/панели.
"""
import argparse
import datetime as dt
import getpass
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.2.0"
COMMANDS = ("run", "setup", "doctor", "status", "rollback", "bridges")

DEFAULT_THRESHOLDS = {"fail_n": 3, "ok_n": 3, "max_dead": 1}
DEFAULT_PROBE = {
    "port": None, "security": "reality", "network": "tcp", "sni": "", "fingerprint": "chrome", "flow": "",
    "public_key": "", "short_id": "", "path": "", "host": "", "service_name": "", "allow_insecure": False,
    "timeout": 12, "port_base": 3140, "urls": ["https://1.1.1.1/cdn-cgi/trace", "https://api.ipify.org"],
}
DEFAULT_PATHS = {"xray": "/opt/bridge-guard/xray", "state": "/var/lib/bridge-guard/state.json",
                 "backups": "/var/lib/bridge-guard/backups"}
DEFAULT_HEARTBEAT = {"url": "", "daily_summary": True, "summary_hour": 9}
UUID_RE = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def is_ip(s):
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


# ──────────────────────────── конфигурация ────────────────────────────

def read_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["thresholds"] = {**DEFAULT_THRESHOLDS, **cfg.get("thresholds", {})}
    cfg["probe"] = {**DEFAULT_PROBE, **cfg.get("probe", {})}
    cfg["paths"] = {**DEFAULT_PATHS, **cfg.get("paths", {})}
    cfg["heartbeat"] = {**DEFAULT_HEARTBEAT, **cfg.get("heartbeat", {})}
    cfg.setdefault("failover", {})
    cfg.setdefault("telegram", {})
    cfg.setdefault("panel", {})
    hosts_fo = cfg["failover"].get("hosts")
    if hosts_fo and "match_address" in hosts_fo and "match_addresses" not in hosts_fo:
        hosts_fo["match_addresses"] = [hosts_fo["match_address"]]
    return cfg


def probe_problems(pr, where):
    out = []
    if not pr.get("port"):
        out.append(f"{where}.port: не задан")
    if pr.get("security") == "reality":
        if not re.match(r"^[A-Za-z0-9_-]{43}$", str(pr.get("public_key") or "")):
            out.append(f"{where}.public_key: не похож на публичный ключ Reality (43 символа base64url)")
        if not re.match(r"^[0-9a-fA-F]{0,16}$", str(pr.get("short_id") or "")):
            out.append(f"{where}.short_id: до 16 hex-символов")
        if not pr.get("sni"):
            out.append(f"{where}.sni: не задан")
    if pr.get("security") not in ("reality", "tls", "none"):
        out.append(f"{where}.security: reality | tls | none")
    if pr.get("network") not in ("tcp", "raw", "ws", "grpc", "xhttp", "httpupgrade"):
        out.append(f"{where}.network: tcp | ws | grpc | xhttp | httpupgrade")
    return out


def validate_config(cfg):
    """Список проблем (пустой = всё в порядке). Ловит и текст-заглушки из примера."""
    problems = []
    br = cfg.get("bridges")
    if br == "auto":
        auto = cfg.get("auto") or {}
        if not (auto.get("countries") or auto.get("profiles") or cfg["panel"].get("profile")):
            problems.append("bridges: auto требует auto.countries (например [\"RU\"]) или auto.profiles, или panel.profile")
    elif not br:
        problems.append("bridges: список мостов пуст (или укажите \"auto\")")
    else:
        for b in br:
            if not b.get("name") or not is_ip(b.get("ip", "")):
                problems.append(f"bridges: у моста нужны name и ip: {b}")
    val = str(cfg["probe"].get("uuid") or "")
    if not re.match(UUID_RE, val):
        problems.append("probe.uuid: не задан или не похож на vlessUuid вида 8-4-4-4-12 (bridge-guard setup заполнит сам)")
    has_panel = bool(cfg["panel"].get("url") and cfg["panel"].get("token"))
    static_bridges = [b for b in (br if isinstance(br, list) else []) if not b.get("profile") and not b.get("probe")]
    if not has_panel or static_bridges:
        # без панели параметры клиента должны быть заданы руками (или у каждого моста свой probe)
        problems += probe_problems(cfg["probe"], "probe")
    for b in (br if isinstance(br, list) else []):
        if b.get("probe"):
            problems += probe_problems({**cfg["probe"], **b["probe"]}, f"bridges[{b.get('name')}].probe")
    fo = cfg["failover"]
    if not fo.get("dns") and not fo.get("hosts"):
        problems.append("failover: не задан ни dns, ни hosts — сторожу нечего переключать")
    needs_panel = bool(fo.get("hosts")) or br == "auto"
    if needs_panel and not (cfg["panel"].get("url") and cfg["panel"].get("token")):
        problems.append("panel.url и panel.token нужны для режима хостов и bridges=auto")
    if fo.get("dns"):
        for key in ("zone", "name", "token_file"):
            if not fo["dns"].get(key):
                problems.append(f"failover.dns.{key}: не задан")
    if fo.get("hosts") and not fo["hosts"].get("match_addresses"):
        problems.append("failover.hosts.match_addresses: пусто")
    if not os.path.exists(cfg["paths"]["xray"]):
        problems.append(f"paths.xray: нет файла {cfg['paths']['xray']} (scripts/install.sh скачает Xray-core)")
    return problems


def load_config(path):
    try:
        cfg = read_config(path)
    except FileNotFoundError:
        print(f"нет конфига {path} — запустите: bridge-guard setup", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"конфиг {path} — не JSON: {e}", file=sys.stderr)
        sys.exit(2)
    problems = validate_config(cfg)
    if problems:
        print("Ошибки конфигурации:\n  - " + "\n  - ".join(problems), file=sys.stderr)
        sys.exit(2)
    return cfg


def write_config(path, cfg):
    """Пишет конфиг, старый — в бэкап рядом."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        bak = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(path, bak)
        print(f"  старый конфиг сохранён: {bak}")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ──────────────────────────── внешние сервисы ─────────────────────────

class Panel:
    """Тонкий клиент Remnawave API: хосты, профили, ноды, сквады, служебный пользователь."""

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

    @staticmethod
    def _list(data, key):
        return data.get(key, data) if isinstance(data, dict) else data

    def hosts(self):
        return self._list(self.call("GET", "/api/hosts"), "hosts")

    def set_host_address(self, uuid, address):
        return self.call("PATCH", "/api/hosts", {"uuid": uuid, "address": address})

    def profiles(self):
        return self._list(self.call("GET", "/api/config-profiles"), "configProfiles")

    def profile(self, name_or_uuid):
        return next((p for p in self.profiles() if name_or_uuid in (p.get("uuid"), p.get("name"))), None)

    def nodes(self):
        return self._list(self.call("GET", "/api/nodes"), "nodes")

    def squads(self):
        return self._list(self.call("GET", "/api/internal-squads"), "internalSquads")

    def user_by_name(self, username):
        try:
            return self.call("GET", "/api/users/by-username/" + urllib.parse.quote(username))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def create_user(self, username, squad_uuids, description):
        expire = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return self.call("POST", "/api/users", {
            "username": username, "activeInternalSquads": squad_uuids, "expireAt": expire,
            "trafficLimitBytes": 0, "trafficLimitStrategy": "NO_RESET", "description": description})

    def delete_user(self, uuid):
        return self.call("DELETE", "/api/users/" + uuid)

    def set_user_squads(self, uuid, squad_uuids):
        return self.call("PATCH", "/api/users", {"uuid": uuid, "activeInternalSquads": sorted(set(squad_uuids))})


def inbound_client_params(prof, inbound, hosts, xray, defaults):
    """Параметры клиента для инбаунда профиля — так же, как их собирает ссылка подписки:
    транспорт и безопасность из профиля, sni/отпечаток/путь — из хоста подписки, если задан."""
    raw = next((x for x in prof["config"].get("inbounds", []) if x.get("tag") == inbound.get("tag")), None)
    if not raw or raw.get("protocol") != "vless":
        return None
    ss = raw.get("streamSettings") or {}
    network = (ss.get("network") or "tcp").lower()
    security = (ss.get("security") or "none").lower()
    host = next((h for h in hosts if (h.get("inbound") or {}).get("configProfileInboundUuid") == inbound.get("uuid")
                 and not h.get("isDisabled")), None) or {}
    pr = {**defaults, "port": raw.get("port") or inbound.get("port"), "security": security, "network": network,
          "fingerprint": host.get("fingerprint") or defaults.get("fingerprint") or "chrome"}
    if security == "reality":
        rs = ss.get("realitySettings") or {}
        pr.update({"sni": host.get("sni") or (rs.get("serverNames") or [""])[0],
                   "short_id": (rs.get("shortIds") or [""])[0],
                   "public_key": xray_public_key(xray, rs.get("privateKey", "")) or ""})
    elif security == "tls":
        ts = ss.get("tlsSettings") or {}
        pr["sni"] = host.get("sni") or ts.get("serverName") or ""
        pr["allow_insecure"] = bool(defaults.get("allow_insecure"))
    if network == "ws":
        ws = ss.get("wsSettings") or {}
        pr["path"], pr["host"] = host.get("path") or ws.get("path") or "/", host.get("host") or (ws.get("headers") or {}).get("Host") or ws.get("host") or ""
    elif network == "grpc":
        pr["service_name"] = (ss.get("grpcSettings") or {}).get("serviceName") or host.get("path") or ""
    elif network == "xhttp":
        xs = ss.get("xhttpSettings") or {}
        pr["path"], pr["host"] = host.get("path") or xs.get("path") or "/", host.get("host") or xs.get("host") or ""
    elif network == "httpupgrade":
        hu = ss.get("httpupgradeSettings") or {}
        pr["path"], pr["host"] = host.get("path") or hu.get("path") or "/", host.get("host") or hu.get("host") or ""
    pr["flow"] = "xtls-rprx-vision" if (security in ("reality", "tls") and network in ("tcp", "raw")) else ""
    pr["inbound_uuid"], pr["inbound_tag"] = inbound.get("uuid"), inbound.get("tag")
    return pr


def pick_inbound(prof, hosts, port=None):
    """Инбаунд профиля: по порту, если задан и есть; иначе тот, на который смотрит больше хостов подписки."""
    inbs = prof.get("inbounds") or []
    if port:
        hit = next((i for i in inbs if i.get("port") == port), None)
        if hit:
            return hit
    def n_hosts(i):
        return sum(1 for h in hosts if (h.get("inbound") or {}).get("configProfileInboundUuid") == i.get("uuid") and not h.get("isDisabled"))
    inbs = sorted(inbs, key=lambda i: (-n_hosts(i), i.get("port") or 0))
    return inbs[0] if inbs else None


def bridges_of(cfg, panel=None):
    """Список мостов с параметрами клиента для пробы.

    bridges: "auto" — ноды из панели: по странам (auto.countries), по профилям (auto.profiles)
             или все ноды профиля panel.profile; параметры клиента — из профиля каждой ноды.
    bridges: [ {name, ip, profile?, probe?} ] — явный список; profile → параметры из панели,
             probe → заданы руками, иначе — общий probe из конфига."""
    br = cfg.get("bridges")
    needs_panel = br == "auto" or any(b.get("profile") for b in (br if isinstance(br, list) else []))
    if needs_panel and panel is None:
        panel = Panel(cfg["panel"]["url"], cfg["panel"]["token"])
    profs = {p["uuid"]: p for p in panel.profiles()} if needs_panel else {}
    by_name = {p["name"]: p for p in profs.values()}
    hosts = panel.hosts() if needs_panel else []
    xray = cfg["paths"]["xray"]
    cache = {}

    def params_for(prof):
        if prof["uuid"] not in cache:
            ib = pick_inbound(prof, hosts, cfg["probe"].get("port"))
            cache[prof["uuid"]] = inbound_client_params(prof, ib, hosts, xray, cfg["probe"]) if ib else None
        return cache[prof["uuid"]]

    out = []
    if br == "auto":
        auto = cfg.get("auto") or {}
        countries = {c.upper() for c in (auto.get("countries") or [])}
        want_profiles = set(auto.get("profiles") or ([cfg["panel"]["profile"]] if cfg["panel"].get("profile") and not countries else []))
        for n in panel.nodes():
            pu = (n.get("configProfile") or {}).get("activeConfigProfileUuid")
            prof = profs.get(pu)
            if not prof or not is_ip(n.get("address") or ""):
                continue
            ok = (countries and (n.get("countryCode") or "").upper() in countries) or                  (want_profiles and (prof["name"] in want_profiles or prof["uuid"] in want_profiles))
            if not ok:
                continue
            pr = params_for(prof)
            if pr:
                out.append({"name": n["name"], "ip": n["address"], "profile": prof["name"], "probe": pr})
    else:
        for b in br:
            pr = None
            if b.get("profile"):
                prof = by_name.get(b["profile"]) or profs.get(b["profile"])
                if not prof:
                    raise RuntimeError(f"профиль «{b['profile']}» моста {b.get('name')} не найден в панели")
                pr = params_for(prof)
            if b.get("probe"):
                pr = {**(pr or cfg["probe"]), **b["probe"]}
            out.append({"name": b["name"], "ip": b["ip"], "profile": b.get("profile"), "probe": pr or dict(cfg["probe"])})
    if not out:
        raise RuntimeError("мосты не найдены — проверьте bridges / auto.countries / panel.profile")
    for b in out:
        b["probe"]["uuid"] = cfg["probe"]["uuid"]
    return out


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


def dns_client(cfg):
    d = cfg["failover"].get("dns")
    if not d:
        return None
    return Cloudflare(d["token_file"], d["zone"], d["name"], d.get("ttl", 60))


def telegram_send(tg, text, quiet=False, prefix="🌉 Сторож мостов\n"):
    """Сообщение админу. Если задан proxy — сначала через него (на российских серверах
    api.telegram.org часто недоступен напрямую), потом напрямую; несколько попыток."""
    if quiet or not tg.get("bot_token") or not tg.get("chat_id"):
        print("  telegram: тихо (quiet или не настроен)")
        return False
    data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": prefix + text,
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

def xray_public_key(xray, private_key):
    out = subprocess.run([xray, "x25519", "-i", private_key], capture_output=True, text=True).stdout
    m = re.search(r"(?:PublicKey\)?|Public key):\s*(\S+)", out)
    return m.group(1) if m else None


def build_outbound(ip, pr, tag="out"):
    """VLESS-outbound клиента под параметры моста: tcp/ws/grpc/xhttp/httpupgrade × reality/tls/none."""
    user = {"id": pr["uuid"], "encryption": "none"}
    if pr.get("flow"):
        user["flow"] = pr["flow"]
    network = pr.get("network") or "tcp"
    ss = {"network": network, "security": pr.get("security") or "none"}
    if ss["security"] == "reality":
        ss["realitySettings"] = {"serverName": pr["sni"], "fingerprint": pr.get("fingerprint") or "chrome",
                                 "publicKey": pr["public_key"], "shortId": pr.get("short_id") or ""}
    elif ss["security"] == "tls":
        ss["tlsSettings"] = {"serverName": pr.get("sni") or ip, "fingerprint": pr.get("fingerprint") or "chrome",
                             "allowInsecure": bool(pr.get("allow_insecure"))}
    if network == "ws":
        ss["wsSettings"] = {"path": pr.get("path") or "/", **({"host": pr["host"]} if pr.get("host") else {})}
    elif network == "grpc":
        ss["grpcSettings"] = {"serviceName": pr.get("service_name") or ""}
    elif network == "xhttp":
        ss["xhttpSettings"] = {"path": pr.get("path") or "/", **({"host": pr["host"]} if pr.get("host") else {})}
    elif network == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": pr.get("path") or "/", **({"host": pr["host"]} if pr.get("host") else {})}
    return {"tag": tag, "protocol": "vless",
            "settings": {"vnext": [{"address": ip, "port": pr["port"], "users": [user]}]},
            "streamSettings": ss}


def probe_bridge(cfg, bridge, local_port):
    """True, если через мост клиент реально выходит в интернет (получен внешний IPv4)."""
    pr = bridge["probe"]
    xcfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": local_port, "protocol": "http", "settings": {}}],
        "outbounds": [build_outbound(bridge["ip"], pr)],
    }
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(xcfg, tmp)
    tmp.close()
    proc = subprocess.Popen([cfg["paths"]["xray"], "run", "-config", tmp.name],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{local_port}"}))
        for url in cfg["probe"]["urls"]:
            try:
                body = opener.open(url, timeout=cfg["probe"]["timeout"]).read().decode(errors="replace")
                if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", body):
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False
    finally:
        proc.kill()
        proc.wait()
        os.unlink(tmp.name)


def probe_all(cfg, bridges, fake_dead=()):
    def one(i_b):
        i, b = i_b
        if b["name"] in fake_dead:
            return b["name"], False
        return b["name"], probe_bridge(cfg, b, cfg["probe"]["port_base"] + i)
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(bridges)))) as ex:
        return dict(ex.map(one, enumerate(bridges)))


# ──────────────────────────── состояние ───────────────────────────────

def load_state(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
    else:
        st = {}
    st.setdefault("bridges", {})
    st.setdefault("switched", None)
    st.setdefault("frozen", False)
    st.setdefault("events", [])
    st.setdefault("stats", {"runs": 0, "events": 0, "since": time.time()})
    return st


def save_state(path, state):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def remember(state, text):
    state["events"] = (state.get("events") or [])[-29:] + [{"at": now_str(), "text": text}]
    state["stats"]["events"] = state["stats"].get("events", 0) + 1


# ──────────────────────────── переключения ────────────────────────────

def backup_hosts(cfg, hosts):
    os.makedirs(cfg["paths"]["backups"], exist_ok=True)
    path = os.path.join(cfg["paths"]["backups"], f"hosts.{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)
    return path


def hosts_switch(cfg, panel, state, dead_ips, to_ip, dry):
    """Хосты с адресом из match_addresses или с IP мёртвого моста → to_ip. Оригиналы — в состояние."""
    match = set(cfg["failover"]["hosts"]["match_addresses"]) | set(dead_ips)
    hosts = panel.hosts()
    todo = [h for h in hosts if h.get("address") in match and h.get("address") != to_ip]
    if not todo:
        return f"хосты: нечего переводить (адресов {', '.join(sorted(match))} среди хостов нет)"
    if dry:
        return f"[dry-run] хостов перевёл бы на {to_ip}: {len(todo)}"
    bpath = backup_hosts(cfg, hosts)
    originals = (state.get("switched") or {}).get("originals") or {}
    for h in todo:
        originals.setdefault(h["uuid"], h.get("address"))
        panel.set_host_address(h["uuid"], to_ip)
    state["switched"] = {"to": to_ip, "originals": originals, "at": now_str(), "backup": bpath}
    return f"хостов переведено на {to_ip}: {len(todo)} (бэкап {os.path.basename(bpath)})"


def hosts_restore(cfg, panel, state, dry):
    sw = state.get("switched") or {}
    originals = sw.get("originals") or {}
    hosts = {h["uuid"]: h for h in panel.hosts()}
    todo = [(u, addr) for u, addr in originals.items() if u in hosts and hosts[u].get("address") != addr]
    if dry:
        return f"[dry-run] хостов вернул бы на исходные адреса: {len(todo)}"
    if todo:
        backup_hosts(cfg, list(hosts.values()))
        for u, addr in todo:
            panel.set_host_address(u, addr)
    state["switched"] = None
    return f"хостов возвращено на исходные адреса: {len(todo)}"


def dns_change(cfg, dns, ip, present, dry):
    """present=False — убрать A-запись мёртвого моста, True — вернуть. Бережём min_pool."""
    if not dns:
        return None
    d = cfg["failover"]["dns"]
    try:
        pool = {r["content"] for r in dns.records()}
        if not present:
            if ip not in pool:
                return f"DNS: {ip} и так нет в {d['name']}"
            if len(pool) - 1 < d.get("min_pool", 1):
                return f"DNS: НЕ убираю {ip} — в пуле осталось бы {len(pool) - 1} < min_pool={d.get('min_pool', 1)}"
            if dry:
                return f"[dry-run] DNS: убрал бы A {d['name']} → {ip}"
            dns.remove(ip)
            return f"DNS: A {d['name']} → {ip} убрана"
        if ip in pool:
            return f"DNS: {ip} уже в {d['name']}"
        if dry:
            return f"[dry-run] DNS: вернул бы A {d['name']} → {ip}"
        dns.add(ip)
        return f"DNS: A {d['name']} → {ip} возвращена"
    except Exception as e:  # noqa: BLE001
        return f"DNS: ошибка — {str(e)[:120]}"


# ──────────────────────────── run ─────────────────────────────────────

def heartbeat(cfg, state, quiet):
    hb = cfg["heartbeat"]
    if hb.get("url"):
        try:
            urllib.request.urlopen(hb["url"], timeout=10).read()
        except Exception as e:  # noqa: BLE001
            print("  heartbeat: не доставлен —", str(e)[:80])
    stats = state["stats"]
    stats["runs"] = stats.get("runs", 0) + 1
    if hb.get("daily_summary") and time.time() - stats.get("since", 0) >= 86400 \
            and time.localtime().tm_hour >= int(hb.get("summary_hour", 9)):
        dead = [n for n, s in state["bridges"].items() if s.get("dead")]
        text = (f"📋 За сутки: проверок {stats['runs']}, событий {stats.get('events', 0)}. "
                f"Сейчас мёртвых мостов: {len(dead)}{' (' + ', '.join(dead) + ')' if dead else ''}. Сторож жив.")
        telegram_send(cfg["telegram"], text, quiet)
        state["stats"] = {"runs": 0, "events": 0, "since": time.time()}


def cmd_run(cfg, dry=False, quiet=False, fake_dead=()):
    th = cfg["thresholds"]
    panel = Panel(cfg["panel"]["url"], cfg["panel"]["token"]) if cfg["panel"].get("url") and cfg["panel"].get("token") else None
    try:
        bridges = bridges_of(cfg, panel)
    except Exception as e:  # noqa: BLE001
        print("мосты не определены:", e, file=sys.stderr)
        return 2
    unknown = set(fake_dead) - {b["name"] for b in bridges}
    if unknown:
        print(f"--fake-dead: нет таких мостов: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    state = load_state(cfg["paths"]["state"])
    st = state["bridges"]
    names = [b["name"] for b in bridges]
    ip_of = {b["name"]: b["ip"] for b in bridges}
    for gone in [n for n in st if n not in names]:
        del st[gone]

    results = probe_all(cfg, bridges, fake_dead)
    for name in names:
        ok = results[name]
        s = st.setdefault(name, {"fails": 0, "oks": 0, "dead": False})
        s["fails"], s["oks"] = (0, s["oks"] + 1) if ok else (s["fails"] + 1, 0)
        if name in fake_dead:
            s["fails"] = max(s["fails"], th["fail_n"])   # репетиция: «мёртв» сразу
        print(f"  {name} {ip_of[name]}: {'ок' if ok else 'ПРОВАЛ'} (провалов подряд {s['fails']}, успехов {s['oks']}, "
              f"{'мёртв' if s['dead'] else 'жив'})")

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

    newly_dead = [n for ev, n in events if ev == "died"]
    if len(dead) > th["max_dead"] and newly_dead:
        if not state.get("frozen"):
            state["frozen"] = True
            msg = (f"🟠 Мёртвых мостов сразу {len(dead)} ({', '.join(dead)}) — больше max_dead={th['max_dead']}. "
                   f"Похоже на проблему сети или самого сторожа, а не мостов. Автодействия ОСТАНОВЛЕНЫ, "
                   f"DNS и хосты не трогаю. Проверьте: bridge-guard doctor.")
            print("  " + msg)
            remember(state, msg)
            telegram_send(cfg["telegram"], msg, quiet)
        if not dry:
            heartbeat(cfg, state, quiet)
            save_state(cfg["paths"]["state"], state)
        return 1
    if state.get("frozen") and len(dead) <= th["max_dead"]:
        state["frozen"] = False
        remember(state, "заморозка снята")
        telegram_send(cfg["telegram"], "🟢 Мостов в норме достаточно — автодействия снова включены.", quiet)
        events += [("died", n) for n in dead if ("died", n) not in events]

    dns = None
    if cfg["failover"].get("dns"):
        try:
            dns = dns_client(cfg)
        except Exception as e:  # noqa: BLE001
            print("  DNS отключён:", str(e)[:100])
    hosts_mode = bool(cfg["failover"].get("hosts")) and panel is not None
    alive_ips = [ip_of[n] for n in alive]
    dead_ips = [ip_of[n] for n in dead]

    for ev, name in events:
        ip = ip_of[name]
        if ev == "died":
            lines = [f"🔴 {name} ({ip}) не проходит проверку {th['fail_n']} раз подряд — клиент через него не выходит в сеть."]
            if alive:
                lines.append(dns_change(cfg, dns, ip, False, dry))
                if hosts_mode:
                    lines.append(hosts_switch(cfg, panel, state, dead_ips, alive_ips[0], dry))
                lines.append(f"Живые мосты: {', '.join(f'{n} ({ip_of[n]})' for n in alive)}. "
                             f"Новые подключения уйдут на них сразу, остальные — при автообновлении подписки.")
            else:
                lines.append("🔴🔴 ЖИВЫХ МОСТОВ НЕТ. Переключать некуда — нужен живой мост.")
        else:
            lines = [f"🟢 {name} ({ip}) снова проходит проверку {th['ok_n']} раз подряд."]
            lines.append(dns_change(cfg, dns, ip, True, dry))
            if hosts_mode and state.get("switched"):
                lines.append(hosts_restore(cfg, panel, state, dry) if not dead
                             else f"хосты остаются на {state['switched']['to']} — ещё есть мёртвые мосты: {', '.join(dead)}")
        lines = [ln for ln in lines if ln]
        print("\n".join("  " + ln for ln in lines))
        remember(state, lines[0])
        telegram_send(cfg["telegram"], "\n".join(lines), quiet)

    if not dry:
        heartbeat(cfg, state, quiet)
        save_state(cfg["paths"]["state"], state)
    sw = state.get("switched")
    print(f"  итог: живы {alive or '—'}, мертвы {dead or '—'}, хосты {'переведены на ' + sw['to'] if sw else 'на своих адресах'}")
    return 1 if dead else 0


# ──────────────────────────── status / rollback ───────────────────────

def cmd_status(cfg):
    state = load_state(cfg["paths"]["state"])
    print(f"bridge-guard {VERSION} — состояние ({cfg['paths']['state']})")
    try:
        bridges = bridges_of(cfg)
    except Exception as e:  # noqa: BLE001
        print("  мосты не определены:", e)
        bridges = [{"name": n, "ip": "?"} for n in state["bridges"]]
    for b in bridges:
        s = state["bridges"].get(b["name"], {"fails": 0, "oks": 0, "dead": False})
        pr = b.get("probe") or {}
        print(f"  {b['name']:<16} {b['ip']:<16} {'МЁРТВ' if s['dead'] else 'жив':<6} провалов подряд {s['fails']}, успехов {s['oks']}"
              f"   :{pr.get('port')} {pr.get('security', '')}/{pr.get('network', '')}")
    sw = state.get("switched")
    print("  хосты:", f"переведены на {sw['to']} в {sw['at']} (исходных адресов: {len(sw.get('originals') or {})})" if sw else "на своих адресах")
    print("  заморозка:", "ДА — автодействия остановлены (bridge-guard doctor)" if state.get("frozen") else "нет")
    print(f"  проверок с последней сводки: {state['stats'].get('runs', 0)}")
    ev = state.get("events") or []
    print("  последние события:" if ev else "  событий ещё не было")
    for e in ev[-10:]:
        print(f"    {e['at']}  {e['text'][:110]}")
    return 0


def cmd_rollback(cfg, dry, yes):
    state = load_state(cfg["paths"]["state"])
    bridges = bridges_of(cfg)
    print("Откат: вернуть хосты на исходные адреса, вернуть A-записи всех мостов, сбросить состояние.")
    if not dry and not yes and input("Продолжить? [y/N] ").strip().lower() not in ("y", "yes", "д", "да"):
        print("отменено")
        return 0
    panel = Panel(cfg["panel"]["url"], cfg["panel"]["token"]) if cfg["failover"].get("hosts") else None
    if panel and state.get("switched"):
        print("  " + hosts_restore(cfg, panel, state, dry))
    elif panel:
        print("  хосты: переведённых нет")
    dns = dns_client(cfg) if cfg["failover"].get("dns") else None
    for b in bridges:
        line = dns_change(cfg, dns, b["ip"], True, dry)
        if line:
            print("  " + line)
    if not dry:
        for s in state["bridges"].values():
            s.update({"fails": 0, "oks": 0, "dead": False})
        state["frozen"] = False
        remember(state, "ручной откат: хосты и DNS возвращены, состояние сброшено")
        save_state(cfg["paths"]["state"], state)
        telegram_send(cfg["telegram"], "↩️ Ручной откат: хосты и DNS возвращены, состояние сброшено.", False)
    print("  готово" if not dry else "  [dry-run] ничего не изменено")
    return 0


# ──────────────────────────── doctor ──────────────────────────────────

def cmd_doctor(config_path, no_telegram=False):
    ok_all = True

    def item(ok, text, hint=""):
        nonlocal ok_all
        ok_all = ok_all and ok
        print(("  ✅ " if ok else "  ❌ ") + text + (f"\n       → {hint}" if (not ok and hint) else ""))

    print(f"bridge-guard {VERSION} — doctor")
    try:
        cfg = read_config(config_path)
    except FileNotFoundError:
        item(False, f"конфиг {config_path}", "запустите: bridge-guard setup")
        return 1
    except json.JSONDecodeError as e:
        item(False, f"конфиг {config_path} — не JSON: {e}")
        return 1
    problems = validate_config(cfg)
    item(not problems, "конфиг валиден", "; ".join(problems))
    if problems:
        return 1
    try:
        st = os.stat(config_path)
        item(not (st.st_mode & 0o077), "права на конфиг 600 (в нём токены)", f"chmod 600 {config_path}")
    except OSError:
        pass

    xray = cfg["paths"]["xray"]
    try:
        ver = subprocess.run([xray, "version"], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        item(True, f"xray запускается: {ver[:60]}")
    except Exception as e:  # noqa: BLE001
        item(False, f"xray не запускается ({xray})", f"{str(e)[:80]}; scripts/install.sh скачает Xray-core")

    panel = None
    prof = None
    if cfg["panel"].get("url") and cfg["panel"].get("token"):
        panel = Panel(cfg["panel"]["url"], cfg["panel"]["token"])
        try:
            profs = panel.profiles()
            item(True, f"панель отвечает, токен принят ({cfg['panel']['url']}, профилей {len(profs)})")
        except Exception as e:  # noqa: BLE001
            item(False, "панель не отвечает или токен не принят", str(e)[:120])
            panel = None
    else:
        print("  ·  панель не настроена (panel.url/token) — режим только DNS")

    try:
        bridges = bridges_of(cfg, panel)
        item(True, f"мостов: {len(bridges)}")
        for b in bridges:
            pr = b["probe"]
            print(f"       {b['name']:<18} {b['ip']:<16} :{pr.get('port')} {pr.get('security')}/{pr.get('network')}"
                  f"{' ' + (pr.get('inbound_tag') or '')}{' профиль ' + b['profile'] if b.get('profile') else ''}")
    except Exception as e:  # noqa: BLE001
        item(False, "мосты не определены", str(e)[:120])
        bridges = []

    if panel and cfg["probe"].get("username"):
        try:
            u = panel.user_by_name(cfg["probe"]["username"])
            if not u:
                item(False, f"служебный пользователь {cfg['probe']['username']} не найден в панели",
                     "bridge-guard setup заведёт его заново")
            else:
                item(u.get("vlessUuid") == cfg["probe"]["uuid"], "служебный пользователь: vlessUuid совпадает с probe.uuid",
                     "в конфиге старый uuid — bridge-guard setup обновит")
                item(str(u.get("status", "")).upper() == "ACTIVE", f"служебный пользователь активен (статус {u.get('status')})",
                     "включите пользователя в панели или продлите срок")
                user_squads = {sq["uuid"] for sq in (u.get("activeInternalSquads") or [])}
                squads = panel.squads()
                for ib_uuid, tag in sorted({(b["probe"].get("inbound_uuid"), b["probe"].get("inbound_tag")) for b in bridges if b["probe"].get("inbound_uuid")}):
                    in_squad = any(sq["uuid"] in user_squads and any(i.get("uuid") == ib_uuid for i in sq.get("inbounds", [])) for sq in squads)
                    item(in_squad, f"служебный пользователь состоит в сквадах инбаунда {tag}",
                         "bridge-guard setup добавит его в нужный сквад")
        except Exception as e:  # noqa: BLE001
            item(False, "проверка служебного пользователя не удалась", str(e)[:120])

    if cfg["failover"].get("dns"):
        d = cfg["failover"]["dns"]
        try:
            st = os.stat(d["token_file"])
            item(not (st.st_mode & 0o077), "файл токена DNS с правами 600", f"chmod 600 {d['token_file']}")
            dns = dns_client(cfg)
            pool = {r["content"] for r in dns.records()}
            item(True, f"Cloudflare: зона {d['zone']} видна, в пуле {d['name']}: {', '.join(sorted(pool)) or 'пусто'}")
            for b in bridges:
                print(f"       {'в пуле   ' if b['ip'] in pool else 'НЕ в пуле'} {b['name']} {b['ip']}")
        except Exception as e:  # noqa: BLE001
            item(False, "DNS Cloudflare", str(e)[:120])
    if cfg["failover"].get("hosts") and panel:
        try:
            match = set(cfg["failover"]["hosts"]["match_addresses"])
            n = sum(1 for h in panel.hosts() if h.get("address") in match)
            item(n > 0, f"хостов подписки с адресами {', '.join(sorted(match))}: {n}",
                 "ни один хост панели не совпал — проверьте failover.hosts.match_addresses")
        except Exception as e:  # noqa: BLE001
            item(False, "хосты панели", str(e)[:120])

    if not no_telegram:
        sent = telegram_send(cfg["telegram"], "🩺 doctor: тестовое сообщение — если вы это видите, доставка работает.", False)
        item(sent, "Telegram доставляет", "проверьте bot_token/chat_id; на серверах в РФ задайте telegram.proxy")

    if bridges and os.path.exists(xray):
        results = probe_all(cfg, bridges)
        for b in bridges:
            ok = results[b["name"]]
            item(ok, f"проба через {b['name']} {b['ip']}: клиент {'выходит' if ok else 'НЕ выходит'} в интернет",
                 "если не выходит через ВСЕ мосты — служебный пользователь не в сквадах или ключи Reality не от этого "
                 "инбаунда; через один — мост мёртв, сторож это и ловит")

    if shutil.which("systemctl"):
        act = subprocess.run(["systemctl", "is-active", "bridge-guard.timer"], capture_output=True, text=True).stdout.strip()
        item(act == "active", f"таймер bridge-guard.timer: {act or 'не установлен'}",
             "systemctl enable --now bridge-guard.timer")
        last = subprocess.run(["systemctl", "show", "-p", "ExecMainExitTimestamp", "bridge-guard.service"],
                              capture_output=True, text=True).stdout.strip().split("=", 1)[-1]
        if last:
            print(f"       последний прогон: {last}")
    state = load_state(cfg["paths"]["state"])
    item(not state.get("frozen"), "заморозки нет", "мёртвых больше max_dead — разберитесь с сетью, затем bridge-guard rollback при необходимости")
    print("\n" + ("  всё в порядке" if ok_all else "  есть проблемы — смотрите строки с ❌"))
    return 0 if ok_all else 1


# ──────────────────────────── setup (мастер) ──────────────────────────

def ask(prompt, default=None, secret=False, yes=False):
    if yes and default is not None:
        return default
    label = f"{prompt} [{default}]: " if default not in (None, "") else f"{prompt}: "
    while True:
        val = (getpass.getpass(label) if secret else input(label)).strip()
        if val:
            return val
        if default is not None:
            return default


def ask_yes(prompt, default=True, yes=False):
    if yes:
        return default
    val = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "д", "да")


def registrable_zone(name):
    parts = name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def cmd_setup(a):
    yes = a.yes
    print(f"bridge-guard {VERSION} — мастер настройки. Ответы по умолчанию — в скобках, Enter = принять.\n")
    cfg = {}
    if os.path.exists(a.config):
        try:
            cfg = read_config(a.config)
            print(f"  найден конфиг {a.config} — значения из него будут предложены по умолчанию")
        except Exception:  # noqa: BLE001
            cfg = {}
    cfg.setdefault("panel", {})
    cfg.setdefault("probe", dict(DEFAULT_PROBE))
    cfg.setdefault("thresholds", dict(DEFAULT_THRESHOLDS))
    cfg.setdefault("failover", {})
    cfg.setdefault("telegram", {})
    cfg.setdefault("paths", dict(DEFAULT_PATHS))
    cfg.setdefault("heartbeat", dict(DEFAULT_HEARTBEAT))
    xray = cfg["paths"]["xray"]
    if not os.path.exists(xray):
        print(f"  ❌ нет бинарника xray ({xray}) — сначала scripts/install.sh")
        return 2

    # 1. панель
    print("── 1/6 Панель Remnawave ──")
    url = a.panel_url or ask("адрес панели (https://panel.example.com)", cfg["panel"].get("url"), yes=yes)
    token = a.token or ask("API-токен панели", cfg["panel"].get("token"), secret=True, yes=yes)
    panel = Panel(url, token)
    try:
        profs = panel.profiles()
        nodes = panel.nodes()
    except Exception as e:  # noqa: BLE001
        print("  ❌ панель не ответила:", str(e)[:120])
        return 2
    print(f"  ✅ панель отвечает, профилей {len(profs)}, нод {len(nodes)}")
    cfg["panel"].update({"url": url.rstrip("/"), "token": token})

    # 2. мосты — ноды панели (обычно те, что в стране клиентов)
    print("\n── 2/6 Мосты ──")
    profs_by_uuid = {p["uuid"]: p for p in profs}
    rows = []
    for n in nodes:
        pu = (n.get("configProfile") or {}).get("activeConfigProfileUuid")
        prof = profs_by_uuid.get(pu)
        if not prof or not is_ip(n.get("address") or ""):
            continue
        rows.append({"name": n["name"], "ip": n["address"], "country": (n.get("countryCode") or "").upper(), "prof": prof})
    if not rows:
        print("  ❌ в панели нет нод с IP-адресом и профилем")
        return 2
    if a.profile:
        rows = [r for r in rows if a.profile in (r["prof"]["name"], r["prof"]["uuid"])] or rows
    countries = {c.strip().upper() for c in (a.countries or "").split(",") if c.strip()}
    if a.bridges:
        wanted = {x.strip() for x in a.bridges.split(",") if x.strip()}
        default_idx = [i for i, r in enumerate(rows, 1) if r["name"] in wanted]
    elif countries:
        default_idx = [i for i, r in enumerate(rows, 1) if r["country"] in countries]
    else:
        ru = [i for i, r in enumerate(rows, 1) if r["country"] == "RU"]
        default_idx = ru or list(range(1, len(rows) + 1))
    for i, r in enumerate(rows, 1):
        print(f"  {i:2}. {'*' if i in default_idx else ' '} {r['name']:<20} {r['ip']:<16} {r['country'] or '--':<4} профиль {r['prof']['name']}")
    print("  (* — предложены по умолчанию; входы платных продуктов и обычные ноды из списка уберите)")
    choice = ask("номера мостов через запятую (те, через которые ходят клиенты)", ",".join(map(str, default_idx)), yes=yes)
    idx = sorted({int(x) for x in re.findall(r"\d+", choice) if 1 <= int(x) <= len(rows)})
    chosen = [rows[i - 1] for i in idx]
    if not chosen:
        print("  ❌ мосты не выбраны")
        return 2
    # как запомнить выбор: «все ноды этих профилей» (точнее всего — мосты обычно делят один профиль),
    # иначе «все ноды этих стран», иначе явный список
    sel_profiles = {r["prof"]["name"] for r in chosen}
    sel_countries = {r["country"] for r in chosen if r["country"]}
    cfg["panel"].pop("profile", None)
    if len([r for r in rows if r["prof"]["name"] in sel_profiles]) == len(chosen):
        cfg["bridges"], cfg["auto"] = "auto", {"profiles": sorted(sel_profiles)}
        print(f"  мосты: все ноды профилей {', '.join(sorted(sel_profiles))} — новые ноды на этих профилях подхватятся сами")
    elif sel_countries and len([r for r in rows if r["country"] in sel_countries]) == len(chosen):
        cfg["bridges"], cfg["auto"] = "auto", {"countries": sorted(sel_countries)}
        print(f"  мосты: все ноды со страной {', '.join(sorted(sel_countries))} — новые подхватятся сами")
    else:
        cfg["bridges"] = [{"name": r["name"], "ip": r["ip"], "profile": r["prof"]["name"]} for r in chosen]
        cfg.pop("auto", None)
        print("  мосты: явный список — новые ноды в панели сторож НЕ подхватит, добавьте их в конфиг")
    bridges = [{"name": r["name"], "ip": r["ip"]} for r in chosen]

    # 3. инбаунд и параметры клиента — из профиля КАЖДОГО моста
    print("\n── 3/6 Инбаунд и параметры клиента ──")
    hosts = panel.hosts()
    def n_hosts(ib):
        return sum(1 for h in hosts if (h.get("inbound") or {}).get("configProfileInboundUuid") == ib.get("uuid") and not h.get("isDisabled"))
    ports = {}
    for r in chosen:
        for ib in r["prof"].get("inbounds") or []:
            raw = next((x for x in r["prof"]["config"].get("inbounds", []) if x.get("tag") == ib.get("tag")), {})
            if raw.get("protocol") != "vless":
                continue
            ports.setdefault(ib.get("port"), {"hosts": 0, "tags": set()})
            ports[ib.get("port")]["hosts"] += n_hosts(ib)
            ports[ib.get("port")]["tags"].add(f"{r['prof']['name']}:{ib['tag']}")
    if not ports:
        print("  ❌ у выбранных мостов нет VLESS-инбаундов")
        return 2
    order = sorted(ports, key=lambda p: (-ports[p]["hosts"], p or 0))
    for i, port in enumerate(order, 1):
        print(f"  {i:2}. :{port:<6} хостов подписки {ports[port]['hosts']:<3} {', '.join(sorted(ports[port]['tags']))[:70]}")
    port = a.port or None
    if not port:
        choice = ask("номер порта, которым пользуется большинство клиентов", "1", yes=yes)
        port = order[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= len(order) else order[0]
    cfg["probe"]["port"] = port
    derived = {}
    need_inbounds = {}
    for r in chosen:
        ib = pick_inbound(r["prof"], hosts, port)
        pr = inbound_client_params(r["prof"], ib, hosts, xray, cfg["probe"]) if ib else None
        if not pr:
            print(f"  ❌ {r['name']}: не удалось собрать параметры клиента из профиля {r['prof']['name']}")
            return 2
        if pr["security"] == "reality" and not pr.get("public_key"):
            print(f"  ❌ {r['name']}: не удалось посчитать публичный ключ Reality (xray x25519)")
            return 2
        derived[r["name"]] = pr
        need_inbounds[pr["inbound_uuid"]] = (r["prof"]["name"], pr["inbound_tag"])
        print(f"  ✅ {r['name']:<20} :{pr['port']} {pr['inbound_tag']:<22} {pr['security']}/{pr['network']}"
              f"{' sni ' + pr['sni'] if pr.get('sni') else ''}{' flow' if pr.get('flow') else ''}")
    for b in bridges:
        b["probe"] = derived[b["name"]]

    # 4. служебный пользователь — в сквадах ВСЕХ нужных инбаундов
    print("\n── 4/6 Служебный пользователь ──")
    username = a.probe_user or ask("имя служебного пользователя", cfg["probe"].get("username") or "bridge-probe", yes=yes)
    squads = panel.squads()
    need_squads = {}
    for ib_uuid, (pname, tag) in need_inbounds.items():
        fitting = [sq for sq in squads if any(i.get("uuid") == ib_uuid for i in sq.get("inbounds", []))]
        if not fitting:
            print(f"  ❌ ни один сквад не содержит инбаунд {pname}:{tag} — клиенты через него не ходят?")
            return 2
        fitting.sort(key=lambda sq: -((sq.get("info") or {}).get("membersCount") or 0))
        need_squads[fitting[0]["uuid"]] = fitting[0]["name"]
    print("  сквады для пробы: " + ", ".join(need_squads.values()))
    user = panel.user_by_name(username)
    if user:
        have = {sq["uuid"] for sq in (user.get("activeInternalSquads") or [])}
        missing = [name for u, name in need_squads.items() if u not in have]
        print(f"  пользователь {username} уже есть" + (f", не хватает сквадов: {', '.join(missing)}" if missing else ""))
        if missing:
            if a.no_user_create or not ask_yes("добавить его в недостающие сквады", True, yes):
                print("  ❌ без сквадов пробы через часть мостов невозможны")
                return 2
            panel.set_user_squads(user["uuid"], list(have | set(need_squads)))
            print("  ✅ сквады обновлены")
    else:
        if a.no_user_create or not ask_yes(f"создать пользователя {username} в сквадах {', '.join(need_squads.values())} (срок 10 лет, без лимита)", True, yes):
            print("  ❌ без служебного пользователя пробы невозможны")
            return 2
        user = panel.create_user(username, list(need_squads), "bridge-guard: служебный пользователь для проверки мостов")
        print(f"  ✅ создан {username}")
    cfg["probe"].update({"uuid": user["vlessUuid"], "username": username})
    for b in bridges:
        b["probe"]["uuid"] = user["vlessUuid"]

    # 5. переключение: DNS-пул и хосты
    print("\n── 5/6 Куда переключать ──")
    bridge_ips = {b["ip"] for b in bridges}
    pool_names = []
    for h in hosts:
        adr = h.get("address") or ""
        if adr and not is_ip(adr) and adr not in pool_names and not h.get("isDisabled"):
            try:
                resolved = {ai[4][0] for ai in socket.getaddrinfo(adr, None, socket.AF_INET)}
            except OSError:
                resolved = set()
            if resolved & bridge_ips:
                pool_names.append(adr)
    dns_cfg = cfg["failover"].get("dns") or {}
    if pool_names:
        print("  DNS-пул найден: " + ", ".join(pool_names) + " (имя из хостов подписки резолвится в IP мостов)")
    name = a.dns_name or ask("имя DNS-пула (пусто — без DNS, только хосты)", dns_cfg.get("name") or (pool_names[0] if pool_names else ""), yes=yes)
    if name:
        zone = ask("зона в Cloudflare", dns_cfg.get("zone") or registrable_zone(name), yes=yes)
        token_file = a.dns_token_file or dns_cfg.get("token_file") or "/etc/bridge-guard/cloudflare.token"
        if not os.path.exists(token_file):
            tok = ask("токен Cloudflare (Edit zone DNS на эту зону)", None, secret=True, yes=False)
            os.makedirs(os.path.dirname(token_file), exist_ok=True)
            with open(token_file, "w") as f:
                f.write(tok.strip() + "\n")
            os.chmod(token_file, 0o600)
        try:
            cf = Cloudflare(token_file, zone, name, dns_cfg.get("ttl", 60))
            pool = {r["content"] for r in cf.records()}
            print(f"  ✅ Cloudflare видит зону; в пуле {name}: {', '.join(sorted(pool)) or 'пусто'}")
            for b in bridges:
                if b["ip"] not in pool:
                    print(f"     ⚠️ {b['name']} {b['ip']} нет в пуле — добавьте A-запись, если мост рабочий")
        except Exception as e:  # noqa: BLE001
            print("  ❌ Cloudflare:", str(e)[:120], "— DNS-режим не включаю")
            name = ""
        if name:
            cfg["failover"]["dns"] = {"provider": "cloudflare", "token_file": token_file, "zone": zone, "name": name,
                                      "ttl": dns_cfg.get("ttl", 60), "min_pool": dns_cfg.get("min_pool", 1)}
    if not name:
        cfg["failover"].pop("dns", None)
    match = sorted(set(pool_names) | bridge_ips | ({name} if name else set())) if not a.no_hosts else []
    if match and ask_yes("переводить и хосты подписки на живой мост (адреса: " + ", ".join(match) + ")", True, yes):
        cfg["failover"]["hosts"] = {"match_addresses": match}
    else:
        cfg["failover"].pop("hosts", None)
    if not cfg["failover"]:
        print("  ❌ ни DNS, ни хостов — сторожу нечего переключать")
        return 2

    # 6. Telegram
    print("\n── 6/6 Telegram ──")
    tg = cfg["telegram"]
    tg["bot_token"] = a.tg_token or ask("токен бота (пусто — без Telegram)", tg.get("bot_token", ""), secret=True, yes=yes)
    if tg["bot_token"]:
        tg["chat_id"] = int(a.tg_chat or ask("chat_id получателя", tg.get("chat_id"), yes=yes))
        tg["proxy"] = a.tg_proxy if a.tg_proxy is not None else (tg.get("proxy") or "")
        if not a.skip_telegram_test:
            if not telegram_send(tg, "✅ Тестовое сообщение мастера настройки — доставка работает.", False):
                if not tg["proxy"] and not yes:
                    tg["proxy"] = ask("не доставилось. HTTP-прокси для api.telegram.org (пусто — оставить как есть)", "", yes=yes)
                    if tg["proxy"]:
                        telegram_send(tg, "✅ Тестовое сообщение мастера настройки — доставка через прокси работает.", False)
    cfg["telegram"] = tg

    write_config(a.config, cfg)
    print(f"\n  ✅ конфиг записан: {a.config}")

    # проверка и репетиция
    print("\n── Проверка по-настоящему ──")
    cfg = load_config(a.config)
    results = probe_all(cfg, bridges_of(cfg, panel))
    for b in bridges:
        print(f"  {'✅' if results[b['name']] else '❌'} {b['name']} {b['ip']}")
    if not any(results.values()):
        print("  ❌ ни один мост не прошёл пробу — bridge-guard doctor подскажет причину")
        return 1
    print("\n── Репетиция отказа (ничего не меняется) ──")
    cmd_run(cfg, dry=True, quiet=True, fake_dead={bridges[0]["name"]})

    if shutil.which("systemctl") and not a.no_enable and ask_yes("включить таймер (проверка раз в минуту)", True, yes):
        r = subprocess.run(["systemctl", "enable", "--now", "bridge-guard.timer"], capture_output=True, text=True)
        print("  ✅ таймер включён" if r.returncode == 0 else f"  ❌ systemctl: {r.stderr.strip()[:120]}")
    print("\nГотово. Проверка: bridge-guard doctor · состояние: bridge-guard status · журнал: journalctl -u bridge-guard.service -f")
    return 0


# ──────────────────────────── CLI ─────────────────────────────────────

def main():
    # --config можно писать и до, и после подкоманды; у подкоманд default=SUPPRESS,
    # иначе их значение по умолчанию затирало бы указанное до подкоманды
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS, help="путь к конфигу (по умолчанию /etc/bridge-guard/config.json)")
    ap = argparse.ArgumentParser(description="bridge-guard — сторож мостов Remnawave (проверка настоящим клиентом)")
    ap.add_argument("--config", default=os.environ.get("BRIDGE_GUARD_CONFIG", "/etc/bridge-guard/config.json"),
                    help="путь к конфигу (по умолчанию /etc/bridge-guard/config.json)")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="прогон (запускает таймер)", parents=[common])
    r.add_argument("--dry-run", action="store_true", help="ничего не менять (DNS, хосты, состояние), только решения")
    r.add_argument("--quiet", action="store_true", help="без Telegram")
    r.add_argument("--fake-dead", default="", help="считать мосты мёртвыми сразу (имена через запятую) — репетиция отказа")
    s = sub.add_parser("setup", help="мастер настройки", parents=[common])
    s.add_argument("--panel-url")
    s.add_argument("--token")
    s.add_argument("--profile", help="ограничить выбор мостов одним профилем")
    s.add_argument("--countries", help="мосты = ноды с этими странами, через запятую (например RU)")
    s.add_argument("--bridges", help="имена мостов через запятую")
    s.add_argument("--port", type=int, help="порт инбаунда, которым пользуются клиенты")
    s.add_argument("--probe-user")
    s.add_argument("--no-user-create", action="store_true")
    s.add_argument("--dns-name")
    s.add_argument("--dns-token-file")
    s.add_argument("--no-hosts", action="store_true")
    s.add_argument("--tg-token")
    s.add_argument("--tg-chat")
    s.add_argument("--tg-proxy")
    s.add_argument("--skip-telegram-test", action="store_true")
    s.add_argument("--no-enable", action="store_true", help="не включать таймер")
    s.add_argument("--yes", "-y", action="store_true", help="принимать значения по умолчанию без вопросов")
    d = sub.add_parser("doctor", help="чек-лист «почему не работает»", parents=[common])
    d.add_argument("--no-telegram", action="store_true")
    sub.add_parser("status", help="состояние и последние события", parents=[common])
    rb = sub.add_parser("rollback", help="вернуть хосты и DNS как было, сбросить состояние", parents=[common])
    rb.add_argument("--dry-run", action="store_true")
    rb.add_argument("--yes", "-y", action="store_true")
    sub.add_parser("bridges", help="список мостов (имя и IP) — для скриптов", parents=[common])

    argv = sys.argv[1:]
    if not any(x in COMMANDS for x in argv):
        argv = ["run"] + argv          # bridge-guard --dry-run  ==  bridge-guard run --dry-run
    a = ap.parse_args(argv)
    if a.cmd == "setup":
        return cmd_setup(a)
    if a.cmd == "doctor":
        return cmd_doctor(a.config, a.no_telegram)
    cfg = load_config(a.config)
    if a.cmd == "status":
        return cmd_status(cfg)
    if a.cmd == "rollback":
        return cmd_rollback(cfg, a.dry_run, a.yes)
    if a.cmd == "bridges":
        for b in bridges_of(cfg):
            print(b["name"], b["ip"], b.get("profile") or "-")
        return 0
    fake = {x.strip() for x in a.fake_dead.split(",") if x.strip()}
    if a.dry_run:
        print("  [dry-run] изменения не применяются")
    elif fake:
        print("  ВНИМАНИЕ: --fake-dead без --dry-run переключит DNS и хосты по-настоящему")
    return cmd_run(cfg, dry=a.dry_run, quiet=a.quiet or a.dry_run, fake_dead=fake)


if __name__ == "__main__":
    sys.exit(main())
