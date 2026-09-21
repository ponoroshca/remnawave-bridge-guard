# Справочник: все команды, флаги, файлы, коды выхода

Собран из исходников (`add_argument`) — то же, что печатает `--help`.

## bridge-guard

```
bridge-guard [--config ПУТЬ] <run|setup|doctor|status|rollback|bridges> [флаги]
```

`--config` — путь к конфигу (по умолчанию `/etc/bridge-guard/config.json` или переменная `BRIDGE_GUARD_CONFIG`); можно писать до и после команды. Без команды выполняется `run` (старый синтаксис `bridge-guard --dry-run` работает). `--version` — версия.

### `bridge-guard run`

| флаг | что делает |
|---|---|
| `--dry-run` | ничего не менять (DNS, хосты, состояние), только решения |
| `--quiet` | без Telegram |
| `--fake-dead` | считать мосты мёртвыми сразу (имена через запятую) — репетиция отказа |

### `bridge-guard setup`

| флаг | что делает |
|---|---|
| `--panel-url` | адрес панели (https://panel.example.com) |
| `--token` | API-токен панели |
| `--profile` | ограничить выбор мостов одним профилем |
| `--countries` | мосты = ноды с этими странами, через запятую (например RU) |
| `--bridges` | имена мостов через запятую |
| `--port` | порт инбаунда, которым пользуются клиенты |
| `--probe-user` | имя служебного пользователя (по умолчанию bridge-probe) |
| `--no-user-create` | не создавать служебного пользователя и не менять его сквады |
| `--dns-name` | имя DNS-пула; пустая строка — без DNS |
| `--dns-token-file` | файл с токеном Cloudflare (по умолчанию /etc/bridge-guard/cloudflare.token) |
| `--dns-create` | создать недостающие A-записи мостов |
| `--no-dns-create` | не создавать A-записи |
| `--create-host` | создать хост подписки на имя пула, если его нет |
| `--no-hosts` | не переводить хосты подписки (только DNS) |
| `--tg-token` | токен Telegram-бота (пустая строка — без Telegram) |
| `--tg-chat` | chat_id получателя; без него мастер определит получателя сам (нажмите Start у бота) |
| `--tg-proxy` | HTTP-прокси для api.telegram.org, например http://127.0.0.1:3128 |
| `--skip-telegram-test` | не слать тестовое сообщение и тестовую тревогу |
| `--no-enable` | не включать таймер |
| `--yes, -y` | принимать значения по умолчанию без вопросов |

### `bridge-guard doctor`

| флаг | что делает |
|---|---|
| `--no-telegram` | не слать тестовое сообщение |

### `bridge-guard rollback`

| флаг | что делает |
|---|---|
| `--dry-run` | только показать, что будет возвращено |
| `--yes, -y` | без подтверждения |

### `bridge-guard status` и `bridge-guard bridges`

Без флагов. `status` — мосты, счётчики, переведённые хосты, последние 10 событий. `bridges` — строки «имя ip профиль» для скриптов.

**Коды выхода.** `run`: 0 — все мосты живы, 1 — есть мёртвые (штатно, таймер это знает), 2 — ошибка конфига/панели. `doctor`: 0 — всё ✅, 1 — есть ❌. `setup`: 0 — готово, 1 — ни один мост не прошёл пробу, 2 — ошибка/отказ. Ctrl+C — 130.

**Файлы.** `/opt/bridge-guard/` — скрипты и xray; `/etc/bridge-guard/config.json` (600); `/etc/bridge-guard/cloudflare.token` (600); `/var/lib/bridge-guard/state.json` — счётчики, заморозка, переведённые хосты и их исходные адреса, убранные сторожем A-записи, кэш мостов, события; `/var/lib/bridge-guard/backups/hosts.<время>.json` — хосты панели перед каждой правкой; `/etc/systemd/system/bridge-guard.service` (oneshot, `SuccessExitStatus=0 1`, `TimeoutStartSec=150`) и `bridge-guard.timer` (`OnUnitActiveSec=60`).

**Переменные окружения.** `BRIDGE_GUARD_CONFIG` — путь к конфигу; для `scripts/install.sh`: `NO_SETUP=1` — не запускать мастер, `XRAY_VERSION=vX.Y.Z` — зафиксировать Xray-core, `BRIDGE_GUARD_SRC_URL` — откуда брать исходники; для `install-exit-probe`: `SSH_PORT`.

**Ключи конфига** — таблица в [README → Конфигурация](../README.md#конфигурация), полный пример `examples/config.example.json`. Значения по умолчанию: `probe.timeout` 12 с, `probe.port_base` 3140, `probe.urls` — `1.1.1.1/cdn-cgi/trace` и `api.ipify.org`, `thresholds` 3/3/1, `failover.dns.ttl` 60, `min_pool` 1, `heartbeat.summary_hour` 9.

## lanes-probe

```
lanes-probe --bridge <имя|IP> [флаги]
```

| флаг | что делает |
|---|---|
| `--bridge` | имя моста из конфига или его IP |
| `--port-base` |  |
| `--timeout` |  |
| `--no-speed` |  |
| `--speed-url` |  |
| `--speed-seconds` |  |

## exit-probe-conf

```
exit-probe-conf --name ИМЯ (--bridge <имя|IP> | --profile ИМЯ) [флаги] > conf.json
```

| флаг | что делает |
|---|---|
| `--profile` | имя или uuid профиля (если не задан --bridge) |
| `--bridge` | IP или имя моста — профиль возьмётся из панели |
| `--name` | как подписывать мост в сообщениях (например RF-1) |
| `--timeout` |  |
| `--attempts` |  |
| `--repeat-hours` |  |

## exit-probe (на мосту)

```
python3 /opt/exit-probe/exit_probe.py [--config ПУТЬ] [--force] [--quiet]
```

| флаг | что делает |
|---|---|
| `--config` |  |
| `--force` | отчёт, даже если всё доступно |
| `--quiet` | без Telegram |

**exit-probe.** Коды выхода: 0 — все exit-ы доступны, 1 — есть недоступные. Файлы на мосту: `/opt/exit-probe/exit_probe.py`, `/etc/exit-probe/config.json` (600: список exit-ов, контрольные точки, `timeout` 5, `attempts` 3, `repeat_hours` 6, telegram), `/var/lib/exit-probe/state.json`; юниты `exit-probe.service/.timer` (раз в 30 мин, первый запуск через 5 мин после загрузки). Переменная `EXIT_PROBE_CONFIG`.

## Скрипты

| скрипт | вызов |
|---|---|
| `scripts/install.sh` | `sudo ./scripts/install.sh` или `curl … \| sudo bash`; переменные `NO_SETUP`, `XRAY_VERSION`, `BRIDGE_GUARD_SRC_URL`; проверяет, что не затирает чужие `bridge-guard.service` и `/usr/local/bin/bridge-guard` |
| `install-exit-probe` | `install-exit-probe <ip-моста> <имя-моста> [ssh-ключ]`; `SSH_PORT=2222`; не затирает чужой `exit-probe.service` на мосту |
| `refresh-exit-probes` | `refresh-exit-probes [ssh-ключ]` — пересобрать зонд на всех мостах из `bridge-guard bridges` |
| `uninstall.sh` | `sudo /opt/bridge-guard/uninstall.sh` — снимает таймер, юниты, `/opt`; про конфиг и состояние спрашивает |
