#!/usr/bin/env bash
# install-exit-probe.sh — поставить зонд exit-нод НА МОСТ (запускать с хоста сторожа).
#
#   install-exit-probe <ip-моста> <имя-моста> [ssh-ключ]
#   install-exit-probe 203.0.113.10 RF-1 ~/.ssh/id_ed25519
#
# Собирает конфиг из профиля этого моста в панели (exit-probe-conf --bridge), копирует зонд, конфиг и
# systemd-юниты на мост по ssh (root), включает таймер и делает пробный прогон в консоль.
# Перезапускать после смены адреса любой ноды — список exit-ов в конфиге статичный.
set -euo pipefail
# работает и из клона (scripts/), и из /opt/bridge-guard (после install.sh)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
[ -f "$HERE/exit_probe.py" ] || HERE="$(cd "$HERE/.." && pwd)"
IP="${1:?ip моста}"; NAME="${2:?имя моста}"; KEY="${3:-}"
# SSH_PORT=2222 — если ssh на мосту не на 22-м порту
SSH="ssh -o BatchMode=yes -o ConnectTimeout=15 -p ${SSH_PORT:-22}"; SCP="scp -q -o BatchMode=yes -o ConnectTimeout=15 -P ${SSH_PORT:-22}"
[ -n "$KEY" ] && { SSH="$SSH -i $KEY"; SCP="$SCP -i $KEY"; }
GEN="$HERE/exit_probe_conf.py"
CONFIG="${BRIDGE_GUARD_CONFIG:-/etc/bridge-guard/config.json}"

tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
umask 077
python3 "$GEN" --config "$CONFIG" --bridge "$IP" --name "$NAME" > "$tmp"
echo "конфиг собран: $(python3 -c "import json,sys; c=json.load(open(sys.argv[1])); print(len(c['exits']), 'exit-ов,', len(c['controls']), 'контроля')" "$tmp")"

# не затираем чужой exit-probe.service, если на мосту уже есть служба с таким именем от другой программы
$SSH "root@$IP" 'f=/etc/systemd/system/exit-probe.service; if [ -f "$f" ] && ! grep -q "/opt/exit-probe/" "$f"; then
  echo "СТОП: на мосту уже есть $f от другой программы — переименуйте её. Ничего не изменено."; exit 3; fi
  mkdir -p /opt/exit-probe /etc/exit-probe /var/lib/exit-probe' || exit $?
$SCP "$HERE/exit_probe.py" "root@$IP:/opt/exit-probe/exit_probe.py"
$SCP "$tmp" "root@$IP:/etc/exit-probe/config.json"
$SCP "$HERE/systemd/exit-probe.service" "$HERE/systemd/exit-probe.timer" "root@$IP:/etc/systemd/system/"
$SSH "root@$IP" 'chmod 755 /opt/exit-probe/exit_probe.py; chmod 600 /etc/exit-probe/config.json;
  systemctl daemon-reload; systemctl enable --now exit-probe.timer >/dev/null 2>&1;
  echo "── пробный прогон на мосту (без Telegram) ──";
  python3 /opt/exit-probe/exit_probe.py --config /etc/exit-probe/config.json --force --quiet || true;
  echo "таймер: $(systemctl is-active exit-probe.timer)"'
