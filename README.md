# MikrotikScripts

To use enter the command into RouterOS terminal.

## 1. DNS server performance test

CheckDNS will find the DNS servers as configured in IP->DNS and test the performance of each one. After that it will run the same tests as if the mikrotik was acting as a local DNS server before providing results.

<code>/tool fetch url="https://raw.githubusercontent.com/MARKJ78/MikrotikScripts/master/checkDNS.rsc" mode=https;/import checkDNS.rsc</code>

## 2. HSIA gateway full health audit

`hsiaCheck.rsc` is the live equivalent of the offline diagnostics report. It scores the gateway on the same weighted dimensions used in `mikrotik-diagnostics.md` (timing 25, system 15, dhcp 15, session/lease 15, interfaces 15, radius 10, dns 5) and prints a 0–100 score with a HEALTHY / WARNINGS / DEGRADED / CRITICAL rating.

It also runs informational checks (no score impact) for:

- AAAoff ip-binding + sync scheduler state
- Walled-garden anti-pattern (`msftconnecttest.com`, `msftncsi.com` — DEF-010)
- VRRP HA failure state

Toggles at the top of the script let you scope a customer-call audit to specific sections.

<code>/tool fetch url="https://raw.githubusercontent.com/MARKJ78/MikrotikScripts/master/hsiaCheck.rsc" mode=https;/import hsiaCheck.rsc</code>