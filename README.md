# MikrotikScripts

To use enter the command into RouterOS terminal.

## 1. DNS server performance test

CheckDNS will find the DNS servers as configured in IP->DNS and test the performance of each one. After that it will run the same tests as if the mikrotik was acting as a local DNS server before providing results.

<code>/tool fetch url="https://raw.githubusercontent.com/MARKJ78/MikrotikScripts/master/checkDNS.rsc" mode=https;/import checkDNS.rsc</code>

## 2. Gateway healthcheck (full read-only diagnostic)

The gateway healthcheck assesses a whole MikroTik guest gateway in one pass — box vitals, LAN-inward checks (DHCP leases, ARP, hotspot session correlation, client-churn characterisation), WAN-outward checks (true first hop, traceroute, per-upstream DNS sweep, L7 fetches) and short control-plane packet captures — then prints a fault-domain VERDICT separating gateway faults from client/AP/RF and upstream causes. Requires RouterOS v7. It runs as a background job, is 100% read-only, and never changes configuration.

<code>/tool fetch url="https://raw.githubusercontent.com/MARKJ78/MikrotikScripts/master/eleven-mikrotik-gw-healthcheck.rsc" mode=https;/import eleven-mikrotik-gw-healthcheck.rsc</code>

Watch live progress in the Winbox Log window (or <code>/log print follow-only where message~"hc:"</code>). After ~5 minutes collect <code>healthcheck-&lt;identity&gt;.txt</code> and the optional <code>healthcheck-dns.pcap</code> / <code>healthcheck-arp.pcap</code> from Files. On an HA pair, run it on both members.