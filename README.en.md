# bridge-guard — bridge watchdog for Remnawave

*Русская версия — [README.md](README.md).*

**Checks your bridges the way clients see them and moves traffic off a dead bridge by itself.**

A bridge (an in-country relay in front of your exit nodes) can die in three ways, and
only one of them is caught by a port check: the host is switched off (port check catches
it), xray hangs (port answers, clients hang), or the provider starts filtering the bridge's
outbound TCP (port answers, panel is happy, clients connect and cannot open a single site).

bridge-guard runs a real xray client (VLESS + Reality) through **every** bridge once a
minute and asks for the external IP. `fail_n` failures in a row → the bridge is dead: its
A record is removed from the DNS pool and/or subscription hosts are pointed at a live
bridge, you get a Telegram message. `ok_n` successes → it is back. If more than `max_dead`
bridges die at once, the guard assumes its own network is the problem and freezes.

Two more tools ship with it:

- **exit-probe** — runs on the bridge, checks TCP reachability of every exit node plus
  two control points, and tells apart "the bridge itself is cut off" from "this node is
  blocked";
- **lanes-probe** — walks every subscription lane through a bridge as a real client and
  prints exit IP, latency and download speed.

Python 3.9+ standard library only + the Xray-core binary. Ubuntu 22.04/24.04, Debian 12.
Remnawave 2.x API. DNS: Cloudflare (other providers are a 30-line class).

```bash
curl -fsSL https://raw.githubusercontent.com/ponoroshca/remnawave-bridge-guard/main/scripts/install.sh | sudo bash
sudo bridge-guard setup      # wizard: finds bridges & keys in the panel, creates the probe user, checks DNS & Telegram
bridge-guard doctor          # checklist with hints when something is off
```

Messages and docs are in Russian — the tool was born from running services for a
Russian audience, where these failure modes are everyday life. MIT.
