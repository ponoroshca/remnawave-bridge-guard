#!/usr/bin/env python3
"""exit-probe — зонд достижимости exit-нод. Запускается НА МОСТУ.

Зачем. Панель считает ноду живой, потому что смотрит на неё из-за границы. А клиент
идёт через мост, и именно с моста нода может быть недоступна: заблокирован её IP,
провайдер режет исходящий TCP, или отрезан сам мост. Пинг тут бесполезен — при
блокировке ТСПУ ICMP как раз проходит. Проверяем TCP-коннект на рабочий порт.

Две контрольные точки отличают «отрезан мост» от «заблокирована нода»:
  • заграничный контроль не открывается, российский открывается → фильтр на IP моста,
    ноды ни при чём;
  • оба не открываются → у моста нет сети вообще;
  • контроль в порядке, а нода нет → проблема ноды (если и с другого моста тоже —
    блокировка по IP ноды).

Молчит, когда всё доступно. О проблеме пишет в Telegram, но не чаще REPEAT_HOURS
для одной и той же проблемы — иначе при долгой блокировке завалит сообщениями.

  exit-probe --config /etc/exit-probe/config.json            # тихо, если всё доступно
  exit-probe --config ... --force                             # отчёт в любом случае
  exit-probe --config ... --force --quiet                     # только в консоль, без Telegram

Конфиг генерирует exit_probe_conf.py на хосте сторожа (из живого профиля панели);
перегенерировать после любой смены адреса ноды.
"""
import argparse
import json
import os
import socket
import sys
import time
import urllib.parse
import urllib.request

VERSION = "1.0.0"
DEFAULT_CONTROLS = [["Cloudflare", "104.16.123.96", 443], ["ya.ru", "77.88.55.242", 443]]


def reachable(host, port, timeout, attempts):
    for i in range(attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except OSError:
            time.sleep(min(1 + i, 3))
        finally:
            s.close()
    return False


def notify(tg, text, attempts=8):
    data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": text, "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    proxy = tg.get("proxy") or None
    last = None
    for i in range(attempts):
        p = proxy if (proxy and i % 2 == 0) else None
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": p} if p else {}))
            opener.open(urllib.request.Request(f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage", data=data),
                        timeout=20).read()
            return
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(min(2 + i, 8))
    raise last


def main():
    ap = argparse.ArgumentParser(description="exit-probe — достижимость exit-нод с моста (TCP, не ping)")
    ap.add_argument("--config", default=os.environ.get("EXIT_PROBE_CONFIG", "/etc/exit-probe/config.json"))
    ap.add_argument("--force", action="store_true", help="отчёт, даже если всё доступно")
    ap.add_argument("--quiet", action="store_true", help="без Telegram")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args()

    with open(a.config, encoding="utf-8") as f:
        conf = json.load(f)
    tg = conf.get("telegram") or {}
    exits = conf.get("exits") or []
    controls = conf.get("controls") or DEFAULT_CONTROLS
    me = conf.get("name") or socket.gethostname()
    timeout = float(conf.get("timeout", 5))
    attempts = int(conf.get("attempts", 3))
    repeat_hours = float(conf.get("repeat_hours", 6))
    state_path = conf.get("state_file") or os.path.join(os.path.dirname(a.config) or ".", "state.json")

    ctl = {tag: reachable(host, int(port), timeout, attempts) for tag, host, port in controls}
    foreign_ok = ctl.get(controls[0][0], True)
    ru_ok = ctl.get(controls[1][0], True) if len(controls) > 1 else True
    for tag, host, port in controls:
        print("  CTL  ", f"{tag} {host}:{port}", "ok" if ctl[tag] else "FAIL")

    bad, good = [], []
    for tag, host, port in exits:
        (good if reachable(host, int(port), timeout, attempts) else bad).append((tag, host, int(port)))
    for tag, host, port in good:
        print("  OK   ", f"{tag} {host}:{port}")
    for tag, host, port in bad:
        print("  FAIL ", f"{tag} {host}:{port}")

    # ключ «той же проблемы» задаём ДО сравнения с прошлым разом: при фильтре на мосту набор
    # упавших нод дребезжит (часть соединений проскакивает), а проблема одна и та же
    if bad and not foreign_ok and ru_ok:
        key = "BRIDGE-FILTERED"
    elif bad and not foreign_ok and not ru_ok:
        key = "BRIDGE-OFFLINE"
    else:
        key = ",".join(sorted(t for t, _, _ in bad))

    send = bool(bad)
    if send and os.path.exists(state_path):
        try:
            with open(state_path) as f:
                st = json.load(f)
            if st.get("key") == key and time.time() - st.get("ts", 0) < repeat_hours * 3600:
                send = False
                print(f"(та же проблема уже отправлена <{repeat_hours:.0f} ч назад, молчу)")
        except Exception:  # noqa: BLE001
            pass

    n_all = len(exits)
    if key == "BRIDGE-FILTERED":
        lines = "\n".join(f"🔴 <b>{t}</b> {h}:{p}" for t, h, p in bad)
        body = (f"<b>Мост {me}: САМ МОСТ отрезан от заграницы</b>\n"
                f"Контроль: {controls[0][0]} не открывается, {controls[1][0] if len(controls) > 1 else 'РФ'} открывается.\n"
                f"Значит фильтр стоит на IP этого моста, exit-ноды ни при чём.\n"
                f"Не открываются отсюда:\n{lines}\n\n"
                f"Лечится: новый/дополнительный IP у МОСТА, не у нод. Сторож мостов должен был увести "
                f"подписку на живой мост — проверьте DNS/хосты.\n\nДоступны: {len(good)} из {n_all}")
    elif key == "BRIDGE-OFFLINE":
        body = (f"<b>Мост {me}: нет сети вообще</b> — не открывается ни один контроль. "
                f"Это не блокировка, это связь/маршрут/файрвол моста.\n\nДоступны: {len(good)} из {n_all}")
    elif bad:
        lines = "\n".join(f"🔴 <b>{t}</b> {h}:{p} — TCP не открывается" for t, h, p in bad)
        body = (f"<b>Мост {me}: exit-ноды недоступны</b>\n{lines}\n\n"
                f"Контроль в порядке — сам мост не отрезан. Пинг при блокировке ТСПУ проходит, "
                f"так что проверять надо именно TCP.\n"
                f"Если та же нода не открывается и с другого моста, а снаружи РФ открыта — блокировка "
                f"по IP ноды, лечится вторым IP у ноды. Если только отсюда — проблема этого моста.\n\n"
                f"Доступны: {len(good)} из {n_all}")
    else:
        body = f"<b>Мост {me}: все exit-ы доступны</b> ({len(good)} из {n_all})"

    if not a.quiet and tg.get("bot_token") and tg.get("chat_id") and (send or (a.force and not bad)):
        try:
            notify(tg, body)
            print("отправлено в Telegram")
            if bad:
                with open(state_path, "w") as f:
                    json.dump({"key": key, "ts": time.time()}, f)
        except Exception as e:  # noqa: BLE001
            print("Telegram не отправился:", e)
    elif not bad:
        print("всё доступно")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
