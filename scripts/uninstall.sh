#!/usr/bin/env bash
# uninstall.sh — снять bridge-guard с хоста сторожа. Конфиг и состояние спрашивает отдельно.
#   sudo /opt/bridge-guard/uninstall.sh          # или sudo ./scripts/uninstall.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "нужен root (sudo)"; exit 1; }
systemctl disable --now bridge-guard.timer 2>/dev/null
rm -f /etc/systemd/system/bridge-guard.service /etc/systemd/system/bridge-guard.timer
systemctl daemon-reload 2>/dev/null
rm -f /usr/local/bin/bridge-guard /usr/local/bin/lanes-probe /usr/local/bin/exit-probe-conf /usr/local/bin/install-exit-probe /usr/local/bin/refresh-exit-probes
rm -rf /opt/bridge-guard
echo "таймер, юниты и /opt/bridge-guard удалены"
ans=""; read -r -p "удалить конфиг и токены (/etc/bridge-guard)? [y/N] " ans; [ "${ans,,}" = y ] && rm -rf /etc/bridge-guard && echo "  /etc/bridge-guard удалён"
ans=""; read -r -p "удалить состояние и бэкапы хостов (/var/lib/bridge-guard)? [y/N] " ans; [ "${ans,,}" = y ] && rm -rf /var/lib/bridge-guard && echo "  /var/lib/bridge-guard удалён"
echo "Хосты и DNS сторож не трогал при удалении: если что-то было переключено — верните через панель/Cloudflare."
