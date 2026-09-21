#!/usr/bin/env bash
# refresh-exit-probes.sh — пересобрать и разложить зонд exit-нод на ВСЕ мосты из конфига сторожа.
#   refresh-exit-probes [ssh-ключ]
# Запускать после смены адреса любой ноды (или по таймеру раз в сутки — см. docs/exit-probe.md).
set -uo pipefail
KEY="${1:-}"
CONFIG="${BRIDGE_GUARD_CONFIG:-/etc/bridge-guard/config.json}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
INST="$HERE/install-exit-probe.sh"; [ -f "$INST" ] || INST="$HERE/scripts/install-exit-probe.sh"
fail=0
while read -r name ip _; do
  [ -n "$ip" ] || continue
  echo "── $name $ip ──"
  "$INST" "$ip" "$name" $KEY || { echo "  ❌ $name: не удалось"; fail=1; }
done < <(bridge-guard --config "$CONFIG" bridges)
exit $fail
