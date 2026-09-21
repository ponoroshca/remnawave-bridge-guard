#!/usr/bin/env bash
# install.sh — установка bridge-guard на хост сторожа (Debian/Ubuntu, root).
#
# Хост сторожа должен стоять ТАМ, ГДЕ СИДЯТ КЛИЕНТЫ (для российской аудитории — в России):
# проверка «настоящим клиентом» имеет смысл только с той же стороны фильтра, что и клиенты.
#
#   из клона репозитория:   sudo ./scripts/install.sh
#   одной строкой:          curl -fsSL https://raw.githubusercontent.com/ponoroshca/remnawave-bridge-guard/main/scripts/install.sh | sudo bash
#   зафиксировать Xray:     XRAY_VERSION=v25.9.11 sudo ./scripts/install.sh
#
# Кладёт скрипты в /opt/bridge-guard, скачивает Xray-core с проверкой контрольной суммы, ставит
# systemd-юниты и, если запущен в терминале, сразу открывает мастер (bridge-guard setup).
#   NO_SETUP=1 — только установить, мастер не запускать.
#
# Что НЕ трогает: ваши панель, ноды, боты, nginx, docker, другие службы. Пишет только в
# /opt/bridge-guard, /etc/bridge-guard, /var/lib/bridge-guard, /usr/local/bin/{bridge-guard,…}
# и два юнита bridge-guard.service/.timer. Если что-то из этого уже занято чужим — останавливается.
set -euo pipefail

OPT=/opt/bridge-guard
ETC=/etc/bridge-guard
VAR=/var/lib/bridge-guard
XRAY_VERSION="${XRAY_VERSION:-latest}"
SRC_URL="${BRIDGE_GUARD_SRC_URL:-https://github.com/ponoroshca/remnawave-bridge-guard/archive/refs/heads/main.tar.gz}"

[ "$(id -u)" = 0 ] || { echo "нужен root (sudo)"; exit 1; }
command -v python3 >/dev/null || { echo "нужен python3"; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "нужен Python 3.9+"; exit 1; }

# ── проверка, что не затираем чужое ─────────────────────────────────────────────
for u in bridge-guard.service bridge-guard.timer; do
  f="/etc/systemd/system/$u"
  if [ -f "$f" ] && ! grep -q "/opt/bridge-guard/" "$f" && ! grep -q "bridge-guard —" "$f"; then
    echo "СТОП: $f уже существует и это не наш юнит (другая программа с тем же именем)."
    echo "      Переименуйте её или удалите юнит, затем запустите установку снова. Ничего не изменено."
    exit 1
  fi
done
for b in bridge-guard lanes-probe exit-probe-conf install-exit-probe refresh-exit-probes; do
  f="/usr/local/bin/$b"
  if [ -e "$f" ] && [ ! -L "$f" ]; then
    echo "СТОП: $f уже существует и это не наша ссылка. Переименуйте его. Ничего не изменено."
    exit 1
  fi
  if [ -L "$f" ] && [[ "$(readlink -f "$f")" != /opt/bridge-guard/* ]]; then
    echo "СТОП: $f ведёт в $(readlink -f "$f") — чужая программа. Ничего не изменено."
    exit 1
  fi
done
for t in curl unzip tar; do
  command -v "$t" >/dev/null || { apt-get update -qq && apt-get install -y -qq "$t"; }
done

# ── откуда брать файлы: из клона рядом или скачать архив репозитория ──────────
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." 2>/dev/null && pwd || true)"
WORK=""
if [ -n "$HERE" ] && [ -f "$HERE/bridge_guard.py" ]; then
  SRC="$HERE"
else
  WORK=$(mktemp -d)
  echo "исходники: $SRC_URL"
  curl -fsSL --retry 3 -o "$WORK/src.tar.gz" "$SRC_URL"
  tar -xzf "$WORK/src.tar.gz" -C "$WORK"
  SRC=$(dirname "$(find "$WORK" -name bridge_guard.py | head -1)")
  [ -n "$SRC" ] || { echo "в архиве нет bridge_guard.py"; exit 1; }
fi
trap '[ -n "$WORK" ] && rm -rf "$WORK"' EXIT

mkdir -p "$OPT" "$ETC" "$VAR/backups"
chmod 700 "$ETC" "$VAR"
install -m 755 "$SRC/bridge_guard.py" "$SRC/lanes_probe.py" "$SRC/exit_probe_conf.py" "$SRC/exit_probe.py" "$OPT/"
install -m 755 "$SRC/scripts/install-exit-probe.sh" "$SRC/scripts/refresh-exit-probes.sh" "$SRC/scripts/uninstall.sh" "$OPT/"
mkdir -p "$OPT/systemd" && install -m 644 "$SRC"/systemd/*.service "$SRC"/systemd/*.timer "$OPT/systemd/"
ln -sf "$OPT/bridge_guard.py" /usr/local/bin/bridge-guard
ln -sf "$OPT/lanes_probe.py" /usr/local/bin/lanes-probe
ln -sf "$OPT/exit_probe_conf.py" /usr/local/bin/exit-probe-conf
ln -sf "$OPT/install-exit-probe.sh" /usr/local/bin/install-exit-probe
ln -sf "$OPT/refresh-exit-probes.sh" /usr/local/bin/refresh-exit-probes
echo "скрипты: $OPT (в PATH: bridge-guard, lanes-probe, exit-probe-conf, install-exit-probe, refresh-exit-probes)"

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

install -m 644 "$SRC/systemd/bridge-guard.service" "$SRC/systemd/bridge-guard.timer" /etc/systemd/system/
systemctl daemon-reload 2>/dev/null || echo "systemd недоступен (контейнер?) — юниты скопированы, включите таймер на настоящем сервере"
echo
if [ "${NO_SETUP:-0}" != 1 ] && [ -t 1 ] && [ -r /dev/tty ]; then
  echo "Запускаю мастер настройки (Ctrl+C — прервать; позже: bridge-guard setup)…"
  echo
  bridge-guard setup </dev/tty || true
else
  echo "Дальше одна команда — мастер всё найдёт сам и проверит:"
  echo "  bridge-guard setup"
fi
