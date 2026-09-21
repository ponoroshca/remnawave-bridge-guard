#!/usr/bin/env bash
# install.sh — установка bridge-guard на хост сторожа (Debian/Ubuntu, root).
#
# Хост сторожа должен стоять ТАМ, ГДЕ СИДЯТ КЛИЕНТЫ (для российской аудитории — в России):
# проверка «настоящим клиентом» имеет смысл только с той же стороны фильтра, что и клиенты.
#
#   sudo ./scripts/install.sh              # установка или обновление
#   XRAY_VERSION=v25.9.11 sudo ./scripts/install.sh   # зафиксировать версию Xray-core
#
# Что делает: кладёт скрипты в /opt/bridge-guard, скачивает Xray-core с проверкой контрольной
# суммы, создаёт /etc/bridge-guard/config.json из примера (если его нет), ставит systemd-юниты.
# Таймер НЕ включает — сначала заполните конфиг и прогоните --dry-run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
OPT=/opt/bridge-guard
ETC=/etc/bridge-guard
VAR=/var/lib/bridge-guard
XRAY_VERSION="${XRAY_VERSION:-latest}"

[ "$(id -u)" = 0 ] || { echo "нужен root (sudo)"; exit 1; }
command -v python3 >/dev/null || { echo "нужен python3"; exit 1; }
for t in curl unzip; do
  command -v "$t" >/dev/null || { apt-get update -qq && apt-get install -y -qq "$t"; }
done

mkdir -p "$OPT" "$ETC" "$VAR/backups"
install -m 755 "$HERE/bridge_guard.py" "$HERE/lanes_probe.py" "$HERE/exit_probe_conf.py" "$HERE/exit_probe.py" "$OPT/"
ln -sf "$OPT/bridge_guard.py" /usr/local/bin/bridge-guard
ln -sf "$OPT/lanes_probe.py" /usr/local/bin/lanes-probe
ln -sf "$OPT/exit_probe_conf.py" /usr/local/bin/exit-probe-conf
echo "скрипты: $OPT (bridge-guard, lanes-probe, exit-probe-conf в PATH)"

# ── Xray-core: проба поднимает настоящий клиент ───────────────────────────────
arch=$(uname -m)
case "$arch" in
  x86_64) asset=Xray-linux-64.zip ;;
  aarch64|arm64) asset=Xray-linux-arm64-v8a.zip ;;
  *) echo "неизвестная архитектура $arch — положите бинарник xray в $OPT/xray вручную"; asset="" ;;
esac
if [ -n "$asset" ]; then
  if [ "$XRAY_VERSION" = latest ]; then
    url="https://github.com/XTLS/Xray-core/releases/latest/download/$asset"
  else
    url="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$asset"
  fi
  tmp=$(mktemp -d)
  echo "Xray-core: $url"
  curl -fsSL --retry 3 -o "$tmp/$asset" "$url"
  curl -fsSL --retry 3 -o "$tmp/$asset.dgst" "$url.dgst"
  want=$(grep -iE '^SHA2?-?256' "$tmp/$asset.dgst" | head -1 | awk '{print $NF}')
  have=$(sha256sum "$tmp/$asset" | awk '{print $1}')
  [ -n "$want" ] && [ "$want" = "$have" ] || { echo "контрольная сумма Xray-core не сошлась — стоп"; rm -rf "$tmp"; exit 1; }
  unzip -qo "$tmp/$asset" xray -d "$tmp"
  install -m 755 "$tmp/xray" "$OPT/xray"
  rm -rf "$tmp"
  echo "Xray-core: $("$OPT/xray" version | head -1)"
fi

# ── конфиг и юниты ─────────────────────────────────────────────────────────────
if [ ! -f "$ETC/config.json" ]; then
  install -m 600 "$HERE/examples/config.example.json" "$ETC/config.json"
  echo "конфиг: создан $ETC/config.json из примера — ЗАПОЛНИТЕ его"
else
  echo "конфиг: $ETC/config.json уже есть, не трогаю"
fi
install -m 644 "$HERE/systemd/bridge-guard.service" "$HERE/systemd/bridge-guard.timer" /etc/systemd/system/
systemctl daemon-reload 2>/dev/null || echo "systemd недоступен (контейнер?) — юниты скопированы, включите таймер на настоящем сервере"
echo
echo "Дальше:"
echo "  1. nano $ETC/config.json            (docs/panel-setup.md — откуда взять uuid/ключи)"
echo "  2. bridge-guard --dry-run             (пробы и решения без изменений)"
echo "  3. bridge-guard --dry-run --fake-dead RF-1   (репетиция отказа)"
echo "  4. systemctl enable --now bridge-guard.timer"
echo "  журнал: journalctl -u bridge-guard.service -f"
