#!/usr/bin/env python3
"""exit-probe-conf — собрать конфиг для exit_probe.py из живого профиля панели.

Читает конфиг сторожа (panel.url/token, telegram), берёт профиль, которым живут мосты,
и печатает готовый JSON для зонда: список exit-outbound'ов (адрес:порт) + контрольные точки.
Outbound'ы с proxySettings (ходят через другой outbound) пропускаются — напрямую с моста
они и не должны открываться.

  exit-probe-conf --name RF-1 --bridge 203.0.113.10 > conf.json        # профиль моста — из панели
  exit-probe-conf --name RF-1 --profile "RF-Bridge" > conf.json         # или явно по имени профиля

Токен бота попадает в вывод — печатать только в файл, не на экран.
"""
import argparse
import json
import os
import sys
import urllib.request

DEFAULT_CONTROLS = [["Cloudflare", "104.16.123.96", 443], ["ya.ru", "77.88.55.242", 443]]


def api(base, token, path):
    req = urllib.request.Request(base.rstrip("/") + path, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=30) as r:
        payload = json.loads(r.read().decode())
    return payload.get("response", payload)


def main():
    ap = argparse.ArgumentParser(description="конфиг exit-probe из профиля Remnawave")
    ap.add_argument("--config", default=os.environ.get("BRIDGE_GUARD_CONFIG", "/etc/bridge-guard/config.json"))
    ap.add_argument("--profile", help="имя или uuid профиля (если не задан --bridge)")
    ap.add_argument("--bridge", help="IP или имя моста — профиль возьмётся из панели")
    ap.add_argument("--name", required=True, help="как подписывать мост в сообщениях (например RF-1)")
    ap.add_argument("--timeout", type=float, default=5)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--repeat-hours", type=float, default=6)
    a = ap.parse_args()

    with open(a.config, encoding="utf-8") as f:
        cfg = json.load(f)
    panel = cfg.get("panel") or {}
    if not (panel.get("url") and panel.get("token")):
        print("в конфиге сторожа нет panel.url / panel.token", file=sys.stderr)
        return 2
    profs = api(panel["url"], panel["token"], "/api/config-profiles")
    profs = profs.get("configProfiles", profs) if isinstance(profs, dict) else profs
    prof = None
    if a.bridge:
        nodes = api(panel["url"], panel["token"], "/api/nodes")
        nodes = nodes.get("nodes", nodes) if isinstance(nodes, dict) else nodes
        node = next((n for n in nodes if a.bridge in (n.get("name"), n.get("address"))), None)
        if not node:
            print(f"мост «{a.bridge}» не найден в панели", file=sys.stderr)
            return 2
        pu = (node.get("configProfile") or {}).get("activeConfigProfileUuid")
        prof = next((p for p in profs if p.get("uuid") == pu), None)
    elif a.profile:
        prof = next((p for p in profs if a.profile in (p.get("uuid"), p.get("name"))), None)
    if not prof:
        print(f"профиль не найден; есть: {', '.join(p.get('name', '?') for p in profs)}", file=sys.stderr)
        return 2

    exits = []
    for o in prof["config"].get("outbounds", []):
        if o.get("proxySettings"):
            continue
        try:
            v = o["settings"]["vnext"][0]
            exits.append([o["tag"], v["address"], int(v["port"])])
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    exits.sort()
    if not exits:
        print("в профиле нет vless-outbound'ов с адресом — проверьте --profile", file=sys.stderr)
        return 2

    conf = {
        "name": a.name,
        "telegram": {k: v for k, v in (cfg.get("telegram") or {}).items() if k in ("bot_token", "chat_id", "proxy")},
        "exits": exits,
        "controls": DEFAULT_CONTROLS,
        "timeout": a.timeout,
        "attempts": a.attempts,
        "repeat_hours": a.repeat_hours,
        "state_file": "/var/lib/exit-probe/state.json",
    }
    print(json.dumps(conf, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
