# ============================================================
# ELEVEN MIKROTIK GW-HEALTHCHECK v1.7  (GENERIC, READ-ONLY)
# One-file gateway diagnostic for any faulty Eleven-connected MikroTik.
# Merges: HSIA capture + LAN/WAN health + the v0 gw-healthcheck (field-
# derived thresholds) + checkDNS upstream sweep + control-plane pcaps.
# (formerly eleven-supercheck) Output feeds the /hsia-diagnose skill.
# v1.1 2026-07-17 - lab-validated on hAP ax2 @ 7.20.8. Fixes from that run:
#   * fetch now runs in a killable sub-job with a 15s cap - a hung fetch
#     stalled the v1.0 report mid-C5 (RouterOS fetch has no timeout)
#   * true first-hop derived from immediate-gw - route gw is often a
#     public IP on Eleven recursive-route configs (8.8.4.4 trick)
#   * lease correlations scoped to HOTSPOT networks - mgmt/connector
#     leases no longer false-positive joined-but-no-portal
#   * driver-safe error counters - generic rx-error reads empty on ax
#   * ttl hop-probe (blank on 7.20.8) replaced with bounded traceroute
#   * portal-root fetch FAIL reclassified informational (non-200 expected)
#   * width-safe detail prints (the capture terminal drops table columns)
# v1.2 2026-07-17 - second lab run (report completed end-to-end). Fixes:
#   * ROS 7.20.8 parser: 'X and Y' with unparenthesised comparisons
#     evaluates WRONG - it false-fired the neighbour-loss verdict and
#     silently suppressed the keepalive>=lease flag. Every and/or
#     operand is now individually parenthesised.
#   * child-job fetch hung without a console sink - children now run
#     fetch as-value AND write to healthcheck-fetchN sink files
#     (removed afterwards); the 15s kill-cap stays as the backstop
#   * sniffer: total-packets read made fault-tolerant (it errored AFTER
#     a successful capture and printed 'failed'); file-name now carries
#     .pcap explicitly (7.20.8 does not append it); guest bridge picked
#     by MOST bound leases instead of first hotspot; 0-packet captures
#     called out as idle-or-wrong-bridge
#   * RADIUS verdict: 0 accepts+rejects with >0 timeouts now noted
# v1.3 2026-07-17 - sync-scheduler awareness (field knowledge from Mark):
#   the ElevenOS 'sync' scheduler (1m interval) STOPS a running sniffer
#   when they overlap. Captures now wait for sync to tick (run-count
#   watch, max 70s) then run inside the clean ~60s gap; each capture
#   also watches for an early kill and REPORTS it instead of pretending
#   the window completed. Manual sync-disable re-run guidance is printed
#   as an engineer action - this script stays read-only and never
#   touches the scheduler.
# v1.4 2026-07-17 - third lab run (was a v1.2 build) analysis:
#   * keepalive>=lease STILL silently false even parenthesised - time
#     '>=' compare distrusted on 7.20.8; rebuilt as integer seconds with
#     plain '>', plus a typeof diagnostic line so the capture proves it
#   * pcap packet count: 'total-packets' is not readable on 7.20.8 -
#     replaced with written file SIZE (~28 bytes = header-only = empty)
#   * C5 fetch: child jobs timed out on ALL urls incl. ones that fetch
#     fine from the report job. Discriminators added: spawn-guard (empty
#     job id = SPAWN-FAIL), scFetchBeg began-marker reported in TIMEOUT
#     lines, sink-file sizes printed before cleanup. Next run shows
#     whether children never start, or start and hang on fetch.
# v1.5 2026-07-17 - LIVE PROGRESS + rolling pass/fail ("I didn't know
#   what it was doing"). The background job now writes 'hc: ...' lines
#   to the BOX LOG at every section, PASS/FLAG verdicts as sections
#   finish, and 'hc: COMPLETE' at the end. Watch live in the Winbox Log
#   window, or:  /log print follow-only where message~"hc:"
#   The same lines land in the report as [hc] rows. If a run dies midway
#   (one field run stopped mid-C3), the last hc: log line + timestamp
#   shows exactly where and when it died.
# v1.6 2026-07-17 - first PRODUCTION run (CCR2116, 2700 leases):
#   report completed, sync-aware pcaps captured real traffic, and the
#   discriminators answered both open mysteries. Fixes from that run:
#   * keepalive-timeout reads as type STR on 7.20.8 -> [:totime] both
#     sides before comparing (root cause of the silent timing check)
#   * fetch HANGS in depth-2 jobs (began=yes, never finishes) ->
#     fetches now run in a parallel DEPTH-1 job spawned at import time;
#     the report polls its result globals (30s cap) and kills it if
#     wedged - hang-immune AND real results
#   * warm-DNS verdict: one slow probe = TTL re-resolve at WAN cost,
#     not daemon latency -> flag only when 3+ of 10 warm probes slow
#   * neighbour verdict: fully-silent (often ICMP-filtered mgmt IPs)
#     split from lossy; new flag for slow LAN infra over 100ms avg
#     (a production run showed a 379ms core hop)
#   * joined-but-no-portal + session ratio: FRESH subset (lease
#     last-seen under 30m) beside raw - 3d leases inflated raw to 1966
#   * dns pcap also captures the hotspot dns REDIRECT to-port (guest
#     queries are post-NAT on the bridge; the production pcap held answers only)
# v1.7 2026-07-21 - CHURN CHARACTERISATION (new section B11) for a
#   production de-association / "one MAC holding several stale IPs" case.
#   Cross-refs ARP(complete) + DHCP leases to list clients holding MULTIPLE
#   IPs, and SPLITS the offenders by MAC type: randomized / locally-
#   administered (guest phones+laptops re-associating = airtime/roaming
#   churn) vs burned-in OUI (IoT/thermostats/APs that likely still sit on
#   the guest VLAN and belong on an IoT VLAN). Surfaces per-offender OUI +
#   host-name, plus DHCP assign/deassign log volume and offered/waiting
#   lease counts (DORA not completing). New verdict lines under the LAN/
#   WIRELESS block; the "resolver fast but churn" summary now also fires on
#   the multi-IP-MAC signal. Still 100% READ-ONLY (get/find/print only).
#   Built after a 21 Jul guest-SSID capture localised a companion issue to 2.4GHz
#   airtime (45% retries) - B11 tells airtime churn apart from an IoT-VLAN
#   placement problem, the two competing causes of guest-bridge churn.
# ------------------------------------------------------------
# REQUIRES RouterOS v7. On v6 use the manual dump set instead
# (hsia-diagnose data-collection.md).
# ------------------------------------------------------------
# HOW TO RUN
#   A) fetch + import (box must reach GitHub):
#      /tool fetch url="https://raw.githubusercontent.com/MARKJ78/MikrotikScripts/master/eleven-mikrotik-gw-healthcheck.rsc" mode=https
#      /import eleven-mikrotik-gw-healthcheck.rsc
#   B) Winbox: drag this .rsc into Files, then in Terminal:
#      /import eleven-mikrotik-gw-healthcheck.rsc
#
# It returns immediately (runs as a BACKGROUND job - no prompts).
# LIVE PROGRESS while it runs: open the Winbox Log window, or terminal:
#   /log print follow-only where message~"hc:"
# One hc: line per section, PASS/FLAG as tests finish, hc: COMPLETE at end.
# WAIT ~5 minutes (up to ~10 if DNS upstreams are dead - that IS a finding;
# includes up to 70s waiting for the ElevenOS sync tick before the pcaps),
# then:  Files ->
#      healthcheck-<identity>.txt     the report (send this back)
#      healthcheck-dns.pcap           30s guest udp/53 capture (optional)
#      healthcheck-arp.pcap           15s guest ARP capture (optional)
# Drag them out of Winbox Files and attach to the ticket.
# On an HA pair, run it on BOTH members (filenames differ by identity).
#
# READ-ONLY: get/find/print/monitor-once/ping/resolve/fetch-to-null only.
# No set/add/remove on any CONFIG. It creates/removes only its own
# background jobs, its hcF* environment markers, and healthcheck-*
# output files. Sniffer captures traffic but changes no routing/hotspot/
# firewall config. Copper cable-test is deliberately OMITTED (it can
# blip a live link).
# The report is COMPLETE only when its last line reads
# "END OF GW-HEALTHCHECK REPORT" - if it ends early, wait and re-pull.
# ============================================================

# ---- clean up outputs from any previous run (never touches config)
:do { /file remove [find where name~"healthcheck-"] } on-error={}

# ---- sanitise identity -> output file name (healthcheck-<identity>.txt)
:local rawid [/system identity get name]
:if ([:len $rawid]=0) do={ :set rawid "gw" }
:local ident ""
:for i from=0 to=([:len $rawid]-1) do={
  :local ch [:pick $rawid $i ($i+1)]
  :if ([:typeof [:find ("abcdefghijklmnop" . "qrstuvwxyzABCDEF" . "GHIJKLMNOPQRSTUV" . "WXYZ0123456789-_") $ch]]="num") do={
    :set ident ($ident . $ch)
  } else={ :set ident ($ident . "-") }
}
:if ([:len $ident]>24) do={ :set ident [:pick $ident 0 24] }
:if ([:len $ident]=0)  do={ :set ident "gw" }
:local fname ("healthcheck-" . $ident)

# ---- L7 fetch tests: run as a SEPARATE depth-1 job (fetch hangs when
# ---- spawned from inside another job - field-proven). Results land in
# ---- globals; the report job reads them at C5 and kills this if wedged.
:do { /system script environment remove [find where name~"^hcF"] } on-error={}
:global hcF1 "pending"
:global hcF2 "pending"
:global hcF3 "pending"
:global hcFjid ""
:do { :global hcFjid [:execute file="healthcheck-fetchlog" script={
  :global hcF1 ; :global hcF2 ; :global hcF3
  :local t1 [:timestamp]
  :do { [/tool fetch url="http://www.msftconnecttest.com/connecttest.txt" output=none as-value] ; :set hcF1 ("OK " . (([:timestamp]-$t1)/1ms) . "ms") } on-error={ :set hcF1 ("FAIL after " . (([:timestamp]-$t1)/1ms) . "ms") }
  :set t1 [:timestamp]
  :do { [/tool fetch url="https://www.gstatic.com/generate_204" output=none as-value] ; :set hcF2 ("OK " . (([:timestamp]-$t1)/1ms) . "ms") } on-error={ :set hcF2 ("FAIL after " . (([:timestamp]-$t1)/1ms) . "ms") }
  :set t1 [:timestamp]
  :do { [/tool fetch url="https://secure.guestinternet.com/" output=none as-value] ; :set hcF3 ("OK " . (([:timestamp]-$t1)/1ms) . "ms") } on-error={ :set hcF3 ("FAIL-fast " . (([:timestamp]-$t1)/1ms) . "ms - TCP+TLS reached it, non-200 root is expected") }
}] } on-error={}

:execute file=$fname script={

# ================= EDIT HERE IF NEEDED =================
:local ANCHORS {"1.1.1.1";"8.8.8.8"}
:local PROBES  {"google.com";"apple.com";"captive.apple.com";"www.msftconnecttest.com";"connectivitycheck.gstatic.com";"secure.guestinternet.com";"logout.net";"cloudflare.com";"microsoft.com";"amazon.com"}
:local CANARY  {"google.com";"apple.com";"bbc.co.uk";"amazon.com"}
# (L7 fetch URLs live in the depth-1 fetch job at the bottom of this file)
:local DOPCAP  true
:local DNSPCAPSECS 30
:local ARPPCAPSECS 15
# ========================================================

# helper: safe key lookup in an as-value array
:local gv do={ :local a $1; :local k $2; :local r "-"; :do { :if ([:typeof ($a->$k)]!="nothing") do={ :set r ($a->$k) } } on-error={}; :return $r }

# helper: sum every available error/drop counter on an ethernet interface
# (counter names vary by driver; generic rx-error reads EMPTY on ax boards)
:local ethsum do={
  :local s 0
  :foreach pn in={"rx-fcs-error";"rx-align-error";"rx-fragment";"rx-overflow";"rx-too-long";"tx-collision";"tx-underrun";"rx-error";"tx-error";"rx-drop";"tx-drop"} do={
    :do { :local v [/interface ethernet get $1 $pn]; :if ([:typeof $v]="num") do={ :set s ($s+$v) } } on-error={}
  }
  :return $s
}

# helper: live progress - one line to the BOX LOG (watch live in Winbox Log
# or '/log print follow-only where message~"hc:"') AND into this report
:local prog do={ :do { :log info ("hc: " . $1) } on-error={} ; :put ("[hc] " . $1) }

# verdict accumulators
:local cpuMax 0; :local memPct 0; :local ctPct 0; :local cachePct 0; :local zeroc 0
:local warmMs 0; :local dnsSrvBad 0; :local cacheFullLog 0; :local staticDns 0; :local warmSlow 0
:local wanLoss 0; :local gwLoss 0; :local mtuRx 0; :local fetchFail 0; :local radTimeout 0; :local radOk 0
:local ghost 0; :local jnp 0; :local jnpFresh 0; :local dhcpConflict 0; :local unauth 0; :local bindByp 0
:local arpTotal 0; :local arpInc 0; :local arpIncPct 0; :local ratioPct 0; :local nb 0; :local na 0
:local kaBad 0; :local stpOff 0; :local l1delta 0; :local movedLog 0; :local conflictLog 0; :local vrrpLog 0
:local netwDown 0; :local nbrTx 0; :local nbrRx 0; :local cliTx 0; :local cliRx 0; :local cliSum 0
:local nbrSilent 0; :local nbrLossy 0; :local nbrSlowIp ""; :local nbrSlowMs 0
:local flapMultiMac 0; :local flapMaxIp 0; :local flapRnd 0; :local flapBurn 0; :local dhcpFlapLog 0
:local flags 0

:put "############################################################"
:put "# ELEVEN MIKROTIK GW-HEALTHCHECK v1.7 (READ-ONLY)"
:put ("# identity  : " . [/system identity get name])
:put ("# generated : " . [/system clock get date] . " " . [/system clock get time])
:do { :put ("# model     : " . [/system routerboard get model] . "  serial=" . [/system routerboard get serial-number]) } on-error={ :put "# model     : (no routerboard - CHR?)" }
:do { :put ("# base MAC  : " . [/interface ethernet get ([/interface ethernet find]->0) orig-mac-address]) } on-error={}
:put ("# routeros  : " . [/system resource get version])
:put "# report for /hsia-diagnose - pair with healthcheck-dns.pcap / healthcheck-arp.pcap + client HAR"
:put "############################################################"

:put ""
[$prog ("STARTED on " . [/system identity get name] . " - ~30 sections follow, ~5 min; hc: COMPLETE = done")]
:put "########## A  THE BOX ##########"
:put ""
[$prog "A1 resource/clock"]
:put "===== A1  RESOURCE / CLOCK ====="
:put ("uptime    : " . [/system resource get uptime])
:if ([/system resource get uptime] < 1d) do={ :put ">>> uptime under 24h - RECENT REBOOT, check A3 + critical log" }
:local memF [/system resource get free-memory]; :local memT [/system resource get total-memory]
:if ($memT>0) do={ :set memPct (($memF*100)/$memT) }
:put ("cpu       : " . [/system resource get cpu-count] . "x " . [/system resource get cpu-frequency] . "MHz  load-now=" . [/system resource get cpu-load] . "%")
:put ("memory    : free " . $memF . " / " . $memT . "  (" . $memPct . "% free)")
:put ("disk      : free " . [/system resource get free-hdd-space] . "  bad-blocks=" . [/system resource get bad-blocks])
:put ("clock     : " . [/system clock get date] . " " . [/system clock get time] . "  tz=" . [/system clock get time-zone-name])
:do { /system ntp client print } on-error={ :put "(ntp client n/a)" }

:put ""
[$prog "A2 cpu sampling (25s incl profile)"]
:put "===== A2  CPU SAMPLING (5x @2s; sustained over 50% = resource pressure) ====="
:for x from=1 to=5 do={ :local c [/system resource get cpu-load]; :if ($c>$cpuMax) do={ :set cpuMax $c }; :put ("  cpu-load=" . $c . "%  free-mem=" . [/system resource get free-memory]); :delay 2s }
:put ">>> per-process CPU (5s sample):"
/tool profile duration=5
:do { :foreach hh in=[/system health find] do={ :put ("  health " . [/system health get $hh name] . " = " . [/system health get $hh value]) } } on-error={ :put "  (no health sensors)" }
:local stA2 "PASS"; :if ($cpuMax>50) do={ :set stA2 "FLAG" }
[$prog ("A2 cpu " . $stA2 . " (max " . $cpuMax . "%)")]

:put ""
[$prog "A3 config-change history + critical log"]
:put "===== A3  RECENT CONFIG CHANGES + CRITICAL LOG (did someone change something?) ====="
:do { /system history print } on-error={ :put "(history n/a)" }
/log print where topics~"critical" or message~"reboot" or message~"power"

:put ""
[$prog "A4 dns daemon config"]
:put "===== A4  DNS DAEMON CONFIG (cause: saturation / blackhole / stale statics) ====="
:local cs [/ip dns get cache-size]; :local cu [/ip dns get cache-used]
:if ($cs>0) do={ :set cachePct (($cu*100)/$cs) }
:put ("cache-size=" . $cs . "KiB  cache-used=" . $cu . "KiB  (" . $cachePct . "% - over 90% = saturation)")
:put ("cache-max-ttl=" . [/ip dns get cache-max-ttl] . "  (hotel std: 1d; default 1w is too long)")
:put ("max-concurrent-queries=" . [/ip dns get max-concurrent-queries] . "  max-tcp=" . [/ip dns get max-concurrent-tcp-sessions])
:put ("query-server-timeout=" . [/ip dns get query-server-timeout] . "  query-total-timeout=" . [/ip dns get query-total-timeout])
:put ("servers=" . [:tostr [/ip dns get servers]] . "  dynamic=" . [:tostr [/ip dns get dynamic-servers]])
:put ("allow-remote-requests=" . [/ip dns get allow-remote-requests] . "  cache-entries=" . [:len [/ip dns cache find]])
:do { :set zeroc [:len [/ip dns cache find where data="0.0.0.0"]] } on-error={}
:put ("0.0.0.0 blackhole cache entries (DEF-001/002 signal): " . $zeroc)
:set staticDns [:len [/ip dns static find]]
:put ("static DNS entries: " . $staticDns . "  (unexpected statics can break portal redirect)")
:if (($staticDns>0) and ($staticDns<21)) do={ /ip dns static print }
:do { :set cacheFullLog [:len [/log find where message~"cache full"]] } on-error={}
:put ("log lines matching cache-full: " . $cacheFullLog)
:local stA4 "PASS"; :if ((($cachePct>90)) or (($zeroc>50)) or (($cacheFullLog>0))) do={ :set stA4 "FLAG" }
[$prog ("A4 dns-daemon " . $stA4 . " (cache " . $cachePct . "% used, blackhole " . $zeroc . ")")]

:put ""
[$prog "A5 conntrack"]
:put "===== A5  CONNTRACK ====="
:local ctT [/ip firewall connection tracking get total-entries]
:local ctM [/ip firewall connection tracking get max-entries]
:if ($ctM>0) do={ :set ctPct (($ctT*100)/$ctM) }
:put ("conntrack " . $ctT . " / " . $ctM . "  (" . $ctPct . "% - over 80% = storm/exhaustion)")
:do { :put ("udp:53 connections now: " . [:len [/ip firewall connection find where protocol=udp dst-port=53]]) } on-error={}
:local stA5 "PASS"; :if ($ctPct>80) do={ :set stA5 "FLAG" }
[$prog ("A5 conntrack " . $stA5 . " (" . $ctPct . "% of max)")]

:put ""
[$prog "A6 timing config (keepalive vs lease)"]
:put "===== A6  TIMING CONFIG (keepalive must be UNDER dhcp lease) ====="
:local ka "-"; :local mck "-"; :local lt "-"
:do { :set ka  [/ip hotspot user profile get [find default=yes] keepalive-timeout] } on-error={}
:do { :set mck [/ip hotspot user profile get [find default=yes] mac-cookie-timeout] } on-error={}
:do { :set lt  [/ip dhcp-server get ([/ip dhcp-server find]->0) lease-time] } on-error={}
:put ("keepalive-timeout=" . $ka . "  mac-cookie-timeout=" . $mck . "  dhcp-lease=" . $lt)
:put ("  (compare-types: keepalive=" . [:typeof $ka] . "  lease=" . [:typeof $lt] . ")")
:do {
  :local kat [:totime $ka]
  :local ltt [:totime $lt]
  :if (([:typeof $kat]="time") and ([:typeof $ltt]="time")) do={
    :local kas ($kat/1s)
    :local lts ($ltt/1s)
    :if ($kas > ($lts - 1)) do={ :set kaBad 1; :put ">>> BAD: keepalive >= lease (session/lease conflict bug class)" }
  } else={ :put (">>> (keepalive/lease not comparable: " . [:typeof $kat] . "/" . [:typeof $ltt] . ")") }
} on-error={ :put ">>> (keepalive/lease compare errored - check the two values manually)" }
:local stA6 "PASS"; :if ($kaBad>0) do={ :set stA6 "FLAG" }
[$prog ("A6 timing " . $stA6)]
:do { :foreach h in=[/ip hotspot find] do={ :put ("hotspot " . [/ip hotspot get $h name] . "  iface=" . [/ip hotspot get $h interface] . "  addresses-per-mac=" . [/ip hotspot get $h addresses-per-mac]) } } on-error={}
:do { /ip hotspot profile print detail } on-error={ :put "(no hotspot profile)" }

:put ""
[$prog "A7 nat/firewall/bypass sanity"]
:put "===== A7  NAT / FIREWALL / BYPASS SANITY ====="
:do { :put ("dst-53 redirect rules : " . [:len [/ip firewall nat find where action=redirect dst-port=53]]) } on-error={ :put "dst-53 redirect rules : (n/a)" }
:put ("masquerade rules      : " . [:len [/ip firewall nat find where action=masquerade]])
:put ("walled-garden returns : " . [:len [/ip firewall nat find where action=return]])
:put (">>> nat redirect detail:")
/ip firewall nat print where action=redirect
:local mgl [:len [/ip firewall mangle find]]
:put ("mangle rules          : " . $mgl . "  (PCC/PBR check - ZD 55902 class)")
:if (($mgl>0) and ($mgl<41)) do={ /ip firewall mangle print }
:put ("filter rules          : " . [:len [/ip firewall filter find]] . "  (input-chain drops below)")
/ip firewall filter print stats where chain=input
:do { :put ("hotspot walled-garden : " . [:len [/ip hotspot walled-garden find]] . " entries  ip-list=" . [:len [/ip hotspot walled-garden ip find]]) } on-error={}
:do { :set bindByp [:len [/ip hotspot ip-binding find where type=bypassed]]; :put ("ip-bindings           : bypassed=" . $bindByp . "  blocked=" . [:len [/ip hotspot ip-binding find where type=blocked]] . "  total=" . [:len [/ip hotspot ip-binding find]]) } on-error={}
:if (($bindByp>0) and ($bindByp<31)) do={ /ip hotspot ip-binding print detail where type=bypassed }
:put (">>> management services (8291 exposure check; detail shows the address restriction):")
:do { /ip service print detail } on-error={ /ip service print }

:put ""
[$prog "A8 schedulers + scripts"]
:put "===== A8  SCHEDULERS / SCRIPTS (ElevenOS sync present?) ====="
/system scheduler print
:do { :put ("system scripts: " . [:len [/system script find]]) } on-error={}
:do { :foreach sc in=[/system script find] do={ :put ("  script: " . [/system script get $sc name]) } } on-error={}

:put ""
[$prog "A9 certificates"]
:put "===== A9  CERTIFICATES (portal TLS) ====="
:do { /certificate print } on-error={ :put "(certificate menu n/a)" }

:put ""
:put "########## B  LAN SIDE - LOOKING INWARD ##########"
:put ""
[$prog "B1 L1 per-port survey"]
:put "===== B1  L1 PER-PORT (link / rate / duplex / errors / flaps / SFP power) ====="
:foreach i in=[/interface ethernet find] do={
  :local n [/interface ethernet get $i name]
  :local run "no"; :do { :if ([/interface get $n running]) do={ :set run "yes" } } on-error={}
  :local ld 0; :do { :set ld [/interface get $n link-downs] } on-error={}
  :if (($run="yes") or ($ld>0)) do={
    :local m ""; :do { :set m [/interface ethernet monitor $i once as-value] } on-error={}
    :local ldt "-"; :do { :set ldt [/interface get $n last-link-down-time] } on-error={}
    :local es 0; :do { :set es [$ethsum $i] } on-error={}
    :put ("  " . $n . " | " . [$gv $m "status"] . " " . [$gv $m "rate"] . " fd=" . [$gv $m "full-duplex"] . " | err+drop=" . $es . " | flaps=" . $ld . " last-down=" . $ldt)
    :local srx [$gv $m "sfp-rx-power"]
    :if ($srx != "-") do={ :put ("      SFP rx=" . $srx . " tx=" . [$gv $m "sfp-tx-power"] . " temp=" . [$gv $m "sfp-temperature"]) }
  }
}
:put ">>> granular ethernet counters (stats-detail word-wraps - survives the narrow capture terminal):"
:do { /interface ethernet print stats-detail } on-error={ /interface print stats }
:put "# copper cable-test OMITTED on purpose (can blip a live link) - manual on suspect DOWN port only:"
:put "#   /interface ethernet cable-test <port> once"

:put ""
[$prog "B2 live error delta (10s)"]
:put "===== B2  L1 LIVE ERROR DELTA (10s; NONZERO = fault active RIGHT NOW) ====="
:local base [:toarray ""]
:foreach i in=[/interface ethernet find where running=yes] do={ :local n [/interface ethernet get $i name]; :set ($base->$n) [$ethsum $i] }
:delay 10s
:foreach i in=[/interface ethernet find where running=yes] do={ :local n [/interface ethernet get $i name]; :local s [$ethsum $i]; :local d ($s - ($base->$n)); :set l1delta ($l1delta + $d); :put ("  " . $n . "   delta=" . $d . "   total-err+drop=" . $s) }
:local stB2 "PASS"; :if ($l1delta>0) do={ :set stB2 "FLAG" }
[$prog ("B2 error-delta " . $stB2 . " (delta " . $l1delta . ")")]

:put ""
[$prog "B3 poe/switch chip"]
:put "===== B3  POE / SWITCH CHIP (board-dependent) ====="
:do { /interface ethernet poe monitor [find] once } on-error={ :put "  (no POE on this board)" }
:do { /interface ethernet switch port print } on-error={ :put "  (no switch-port view)" }

:put ""
[$prog "B4 bridge/stp/vlan"]
:put "===== B4  L2 BRIDGE / STP / VLAN ====="
:foreach b in=[/interface bridge find] do={
  :local pm [/interface bridge get $b protocol-mode]
  :if ([:tostr $pm]="none") do={ :set stpOff ($stpOff+1) }
  :put ("  bridge " . [/interface bridge get $b name] . "  protocol-mode=" . $pm . "  vlan-filtering=" . [/interface bridge get $b vlan-filtering])
}
/interface bridge port print
:put (">>> bridge vlans: " . [:len [/interface bridge vlan find]])
:local bhc [:len [/interface bridge host find]]
:put (">>> bridge host MACs total: " . $bhc . "   per-port census:")
:if ($bhc<3001) do={
  :local portc [:toarray ""]
  :do { :foreach bh in=[/interface bridge host find] do={ :local ifc "?"; :do { :set ifc [:tostr [/interface bridge host get $bh on-interface]] } on-error={ :do { :set ifc [:tostr [/interface bridge host get $bh interface]] } on-error={} }; :if ([:typeof ($portc->$ifc)]="nothing") do={ :set ($portc->$ifc) 1 } else={ :set ($portc->$ifc) (($portc->$ifc)+1) } } } on-error={}
  :foreach k,v in=$portc do={ :put ("    " . $k . " = " . $v . " MACs") }
} else={ :put "    (census skipped - table over 3000)" }

:put ""
[$prog "B5 LAN neighbour discovery + pings"]
:put "===== B5  LAN NEIGHBOURS (MNDP/LLDP/CDP - what infra does this box SEE?) ====="
:local nbrmap [:toarray ""]
:put ("neighbours discovered: " . [:len [/ip neighbor find]])
:do { :foreach n in=[/ip neighbor find] do={
  :local nad ""; :do { :set nad [:tostr [/ip neighbor get $n address]] } on-error={}
  :local nid ""; :do { :set nid [:tostr [/ip neighbor get $n identity]] } on-error={}
  :local nif ""; :do { :set nif [:tostr [/ip neighbor get $n interface]] } on-error={}
  :local npl ""; :do { :set npl [:tostr [/ip neighbor get $n platform]] } on-error={}
  :put ("  " . $nif . "  " . $nad . "  " . $nid . "  " . $npl)
  :if (([:len $nad]>0) and ([:typeof [:find $nad ":"]]!="num")) do={ :set ($nbrmap->$nad) 1 }
} } on-error={ :put "  (neighbour discovery n/a)" }
:put ">>> ping discovered neighbours (LAN infra reachability, max 8):"
:local nc 0
:foreach nip,x in=$nbrmap do={
  :if ($nc<8) do={
    :set nc ($nc+1); :set nbrTx ($nbrTx+2)
    :local rx 0; :local sum 0
    :do { :foreach p in=[/ping address=$nip count=2 as-value] do={ :do { :local tt ($p->"time"); :if ([:typeof $tt]="time") do={ :set rx ($rx+1); :set sum ($sum+($tt/1ms)) } } on-error={} } } on-error={}
    :set nbrRx ($nbrRx+$rx)
    :local avg "-"; :if ($rx>0) do={ :set avg (($sum/$rx) . "ms") }
    :put ("  " . $nip . "  rx=" . $rx . "/2  avg=" . $avg)
    :if ($rx=0) do={ :set nbrSilent ($nbrSilent+1) }
    :if ($rx=1) do={ :set nbrLossy ($nbrLossy+1) }
    :if ($rx>0) do={ :local am ($sum/$rx); :if ($am>$nbrSlowMs) do={ :set nbrSlowMs $am; :set nbrSlowIp $nip } }
  }
}

:put ""
[$prog ("B5 neighbours INFO (replies " . $nbrRx . "/" . $nbrTx . ")")]
[$prog "B6 arp analysis"]
:put "===== B6  ARP (churn / conflict / proxy-ARP signals) ====="
:set arpTotal [:len [/ip arp find]]
:set arpInc [:len [/ip arp find where complete=no]]
:if ($arpTotal>0) do={ :set arpIncPct (($arpInc*100)/$arpTotal) }
:put ("arp total=" . $arpTotal . "  incomplete=" . $arpInc . "  (" . $arpIncPct . "% - over 5% moderate, over 10% high)")
:local ipdup 0
:if ($arpTotal<3001) do={
  :local ipseen [:toarray ""]
  :do { :foreach r in=[/ip arp find where complete=yes] do={ :local ad [:tostr [/ip arp get $r address]]; :if ([:typeof ($ipseen->$ad)]="nothing") do={ :set ($ipseen->$ad) 1 } else={ :set ipdup ($ipdup+1) } } } on-error={}
}
:put ("IPs seen with more than one MAC (conflict signal): " . $ipdup)
:local stB6 "PASS"; :if (((($arpIncPct>5)) and (($arpTotal>49))) or (($ipdup>0))) do={ :set stB6 "FLAG" }
[$prog ("B6 arp " . $stB6 . " (incomplete " . $arpIncPct . "%, ip-dup " . $ipdup . ")")]

:put ""
[$prog "B7 dhcp pools/leases/conflicts"]
:put "===== B7  DHCP (pools / leases / conflicts / what clients are HANDED) ====="
:do { :foreach s in=[/ip dhcp-server find] do={ :put ("  server " . [/ip dhcp-server get $s name] . "  iface=" . [/ip dhcp-server get $s interface] . "  pool=" . [/ip dhcp-server get $s address-pool] . "  lease=" . [/ip dhcp-server get $s lease-time]) } } on-error={}
/ip pool print
:put ">>> dhcp networks (dns + gateway handed to clients - wrong dns here breaks portal):"
/ip dhcp-server network print detail
:set nb [:len [/ip dhcp-server lease find where status=bound]]
:set dhcpConflict [:len [/ip dhcp-server lease find where status=conflict]]
:put ("leases: bound=" . $nb . "  conflict=" . $dhcpConflict . "  waiting=" . [:len [/ip dhcp-server lease find where status=waiting]] . "  (conflict over 3 investigate, over 10 critical)")
:do { :put ("dhcp alerts configured: " . [:len [/ip dhcp-server alert find]] . "  (rogue-dhcp detection)") } on-error={}
:local stB7 "PASS"; :if ($dhcpConflict>3) do={ :set stB7 "FLAG" }
[$prog ("B7 dhcp " . $stB7 . " (bound " . $nb . ", conflicts " . $dhcpConflict . ")")]

:put ""
[$prog "B8 hotspot session correlation"]
:put "===== B8  HOTSPOT SESSION CORRELATION (cross-ref checks - the portal money-section) ====="
:set na [:len [/ip hotspot active find]]
:local hsIfs [:toarray ""]
:do { :foreach hsx in=[/ip hotspot find] do={ :set ($hsIfs->[:tostr [/ip hotspot get $hsx interface]]) 1 } } on-error={}
:local hsSrv [:toarray ""]
:do { :foreach sx in=[/ip dhcp-server find] do={ :if ([:typeof ($hsIfs->[:tostr [/ip dhcp-server get $sx interface]])]!="nothing") do={ :set ($hsSrv->[:tostr [/ip dhcp-server get $sx name]]) 1 } } } on-error={}
:local nbHs 0
:local nbFresh 0
:do { :foreach l in=[/ip dhcp-server lease find where status=bound] do={ :if ([:typeof ($hsSrv->[:tostr [/ip dhcp-server lease get $l server]])]!="nothing") do={
  :set nbHs ($nbHs+1)
  :do { :local lsn [:totime [/ip dhcp-server lease get $l last-seen]]; :if ([:typeof $lsn]="time") do={ :if ($lsn<30m) do={ :set nbFresh ($nbFresh+1) } } } on-error={}
} } } on-error={}
:if ($nbHs>0) do={ :set ratioPct (($na*100)/$nbHs) }
:local ratioFresh 0
:if ($nbFresh>0) do={ :set ratioFresh (($na*100)/$nbFresh) }
:local hh 0; :do { :set hh [:len [/ip hotspot host find]] } on-error={}
:do { :set unauth [:len [/ip hotspot host find where authorized=no]] } on-error={}
:put ("hotspot: active=" . $na . "  hosts=" . $hh . "  hosts-unauthorized=" . $unauth . "  cookies=" . [:len [/ip hotspot cookie find]])
:put ("active/bound on HOTSPOT networks: raw = " . $na . "/" . $nbHs . " = " . $ratioPct . "%   FRESH (lease seen under 30m) = " . $na . "/" . $nbFresh . " = " . $ratioFresh . "%")
:put ("  (65-75 healthy; over 115 = session leak; under 40 with real occupancy = portal delivery problem; long lease times inflate the raw figure)")
:local leaseMac [:toarray ""]
:if ($nb<4001) do={
  :do { :foreach l in=[/ip dhcp-server lease find where status=bound] do={ :if ([:typeof ($hsSrv->[:tostr [/ip dhcp-server lease get $l server]])]!="nothing") do={ :set ($leaseMac->[:tostr [/ip dhcp-server lease get $l address]]) [/ip dhcp-server lease get $l mac-address] } } } on-error={}
  :do { :foreach a in=[/ip hotspot active find] do={ :local aip [:tostr [/ip hotspot active get $a address]]; :if (([:typeof ($leaseMac->$aip)]!="nothing") and (($leaseMac->$aip)!=[/ip hotspot active get $a mac-address])) do={ :set ghost ($ghost+1) } } } on-error={}
  :put ("GHOSTING - active MAC differs from lease MAC on same IP: " . $ghost . "  (over 0 = IP conflict / AP proxy-ARP / DEF-008)")
  :local arpIp [:toarray ""]
  :do { :foreach r in=[/ip arp find] do={ :set ($arpIp->[:tostr [/ip arp get $r address]]) 1 } } on-error={}
  :local hhIp [:toarray ""]
  :do { :foreach h in=[/ip hotspot host find] do={ :set ($hhIp->[:tostr [/ip hotspot host get $h address]]) 1 } } on-error={}
  :do { :foreach l in=[/ip dhcp-server lease find where status=bound] do={ :if ([:typeof ($hsSrv->[:tostr [/ip dhcp-server lease get $l server]])]!="nothing") do={ :local lip [:tostr [/ip dhcp-server lease get $l address]]; :if (([:typeof ($arpIp->$lip)]!="nothing") and ([:typeof ($hhIp->$lip)]="nothing")) do={ :set jnp ($jnp+1); :do { :local lsn [:totime [/ip dhcp-server lease get $l last-seen]]; :if ([:typeof $lsn]="time") do={ :if ($lsn<30m) do={ :set jnpFresh ($jnpFresh+1) } } } on-error={} } } } } on-error={}
  :put ("JOINED-BUT-NO-PORTAL - hotspot-net bound lease + ARP but absent from hotspot-host: raw=" . $jnp . "  FRESH(lease seen under 30m)=" . $jnpFresh)
  :put ("  (over 0 = client has IP + L2 yet portal never fired: device CNA/VPN, walled-garden hole, redirect break, or wireless side)")
} else={ :put "  (correlation skipped - lease table over 4000)" }

:put ""
:local stB8 "PASS"; :if ((($jnpFresh>0)) or (($ghost>0))) do={ :set stB8 "FLAG" }
[$prog ("B8 portal-correlation " . $stB8 . " (fresh-jnp " . $jnpFresh . " of raw " . $jnp . ", ghosting " . $ghost . ")")]
[$prog "B9 guest-device RTT sample"]
:put "===== B9  CLIENT PATH RTT SAMPLE (OUTSIDE the box: gateway -> guest device over AP/wireless) ====="
:put ">>> ping up to 8 authenticated clients; caveat: sleeping phones drop pings - read RTT of RESPONDERS, not loss"
:local cips [:toarray ""]
:local ccnt 0
:do { :foreach a in=[/ip hotspot active find] do={ :if ($ccnt<8) do={ :set ($cips->$ccnt) [:tostr [/ip hotspot active get $a address]]; :set ccnt ($ccnt+1) } } } on-error={}
:if ($ccnt=0) do={ :put "  (no active hotspot clients to sample)" }
:foreach cip in=$cips do={
  :set cliTx ($cliTx+2)
  :local rx 0; :local sum 0
  :do { :foreach p in=[/ping address=$cip count=2 as-value] do={ :do { :local tt ($p->"time"); :if ([:typeof $tt]="time") do={ :set rx ($rx+1); :set sum ($sum+($tt/1ms)) } } on-error={} } } on-error={}
  :set cliRx ($cliRx+$rx); :set cliSum ($cliSum+$sum)
  :local avg "-"; :if ($rx>0) do={ :set avg (($sum/$rx) . "ms") }
  :put ("  " . $cip . "  rx=" . $rx . "/2  avg=" . $avg)
}

:put ""
[$prog ("B9 client-rtt INFO (replies " . $cliRx . "/" . $cliTx . ")")]
[$prog "B10 L2 log scan"]
:put "===== B10  L2 LOG SCAN (loops / MAC moves / conflicts) ====="
:do { :set movedLog [:len [/log find where message~"moved" or message~"loop" or message~"own address"]] } on-error={}
:do { :set conflictLog [:len [/log find where message~"conflict"]] } on-error={}
/log print where message~"conflict" or message~"moved" or message~"loop" or message~"own address" or message~"alert" or topics~"interface"

:put ""
[$prog "B11 churn characterisation (which clients flap)"]
:put "===== B11  CHURN CHARACTERISATION (MAC<->IP flap; randomized-guest vs burned-in-OUI IoT) ====="
:put ">>> answers the 'one MAC holding several stale IPs' screenshot, and splits the two competing"
:put ">>> Subscriber-churn causes: randomized-MAC guests re-associating (airtime/roaming) vs burned-in"
:put ">>> OUI IoT/thermostats/APs that likely still sit on the guest VLAN (they belong on an IoT VLAN)."
:local macIpStr [:toarray ""]
:local macIpCnt [:toarray ""]
# source 1: ARP (complete entries carry a MAC) - the exact table the customer screenshotted
:if ($arpTotal<8001) do={
  :do { :foreach r in=[/ip arp find where complete=yes] do={
    :local am [:tostr [/ip arp get $r mac-address]]
    :local ad [:tostr [/ip arp get $r address]]
    :if (([:len $am]>0) and ([:len $ad]>0) and ([:typeof [:find $ad ":"]]!="num")) do={
      :if ([:typeof ($macIpStr->$am)]="nothing") do={ :set ($macIpStr->$am) (" " . $ad . " "); :set ($macIpCnt->$am) 1 } else={
        :if ([:typeof [:find ($macIpStr->$am) (" " . $ad . " ")]]!="num") do={ :set ($macIpStr->$am) (($macIpStr->$am) . $ad . " "); :set ($macIpCnt->$am) (($macIpCnt->$am)+1) }
      }
    }
  } } on-error={}
}
# source 2: DHCP leases (all statuses) - catches a MAC that has held several IPs over time
:if ($nb<6001) do={
  :do { :foreach l in=[/ip dhcp-server lease find] do={
    :local lm [:tostr [/ip dhcp-server lease get $l mac-address]]
    :local li [:tostr [/ip dhcp-server lease get $l address]]
    :if (([:len $lm]>0) and ([:len $li]>0)) do={
      :if ([:typeof ($macIpStr->$lm)]="nothing") do={ :set ($macIpStr->$lm) (" " . $li . " "); :set ($macIpCnt->$lm) 1 } else={
        :if ([:typeof [:find ($macIpStr->$lm) (" " . $li . " ")]]!="num") do={ :set ($macIpStr->$lm) (($macIpStr->$lm) . $li . " "); :set ($macIpCnt->$lm) (($macIpCnt->$lm)+1) }
      }
    }
  } } on-error={}
}
# report MACs holding >1 IP; classify randomized (LA/local-admin bit set in octet-1's 2nd hex char) vs burned-in OUI
:local shown 0
:foreach mac,cnt in=$macIpCnt do={
  :if ($cnt>1) do={
    :set flapMultiMac ($flapMultiMac+1)
    :if ($cnt>$flapMaxIp) do={ :set flapMaxIp $cnt }
    :local c2 [:pick $mac 1 2]
    :local rnd false
    :if ([:typeof [:find "2 3 6 7 a b e f A B E F" $c2]]="num") do={ :set rnd true }
    :if ($rnd=true) do={ :set flapRnd ($flapRnd+1) } else={ :set flapBurn ($flapBurn+1) }
    :if ($shown<25) do={
      :set shown ($shown+1)
      :local tag "burned-in-OUI (IoT/AP/TV candidate)"; :if ($rnd=true) do={ :set tag "randomized-MAC (guest phone/laptop)" }
      :local nm "-"; :do { :local lf [/ip dhcp-server lease find where mac-address=$mac]; :if ([:len $lf]>0) do={ :local h [:tostr [/ip dhcp-server lease get ($lf->0) host-name]]; :if ([:len $h]>0) do={ :set nm $h } } } on-error={}
      :put ("  " . $mac . "  ips=" . $cnt . "  [" . ($macIpStr->$mac) . "]  oui=" . [:pick $mac 0 8] . "  " . $tag . "  host=" . $nm)
    }
  }
}
:put ("MACs holding >1 IP: " . $flapMultiMac . "   max IPs on one MAC: " . $flapMaxIp . "   split -> randomized(guest)=" . $flapRnd . "  burned-in(IoT/AP)=" . $flapBurn)
:put ("  (burned-in offenders => IoT/thermostats/APs still on the guest VLAN: move to IoT VLAN/SSID. randomized offenders => guest re-association: usually airtime/roaming - fix RF.)")
# (two simple where-counts - ROS find-where does not reliably group 'and (a or b)')
:do { :set dhcpFlapLog [:len [/log find where message~"deassigned"]] } on-error={}
:do { :set dhcpFlapLog ($dhcpFlapLog + [:len [/log find where message~"offering"]]) } on-error={}
:put ("DHCP deassign/offer log lines in buffer: " . $dhcpFlapLog . "  (high = lease thrash - clients not completing/holding DORA)")
:local offered [:len [/ip dhcp-server lease find where status=offered]]
:local waiting2 [:len [/ip dhcp-server lease find where status=waiting]]
:put ("leases stuck offered=" . $offered . "  waiting=" . $waiting2 . "  (nonzero alongside churn = DORA not completing: lossy air or rogue DHCP)")
:local stB11 "PASS"; :if ((($flapMaxIp>2)) or (($flapMultiMac>5)) or (($dhcpFlapLog>50))) do={ :set stB11 "FLAG" }
[$prog ("B11 churn " . $stB11 . " (multi-IP MACs " . $flapMultiMac . ", max " . $flapMaxIp . ", randomized " . $flapRnd . "/burned " . $flapBurn . ")")]

:put ""
:put "########## C  WAN SIDE - LOOKING OUTWARD ##########"
:put ""
[$prog "C1 routes/wan config/netwatch"]
:put "===== C1  ROUTES / WAN CONFIG / NETWATCH ====="
:local wangw ""
:foreach r in=[/ip route find where dst-address="0.0.0.0/0"] do={
  :if (([:len $wangw]=0) and ([/ip route get $r active])) do={ :set wangw [:tostr [/ip route get $r gateway]] }
  :put ("  default via " . [/ip route get $r gateway] . "  dist=" . [/ip route get $r distance] . "  active=" . [/ip route get $r active] . "  check-gw=" . [/ip route get $r check-gateway])
}
:local fhop ""
:do { :local ig [:tostr [/ip route get ([find where dst-address="0.0.0.0/0" and active=yes]->0) immediate-gw]]; :put ("  immediate-gw: " . $ig); :local pcx [:find $ig "%"]; :if ([:typeof $pcx]="num") do={ :set fhop [:pick $ig 0 $pcx] } else={ :set fhop $ig } } on-error={}
:if ([:len $fhop]=0) do={ :do { :set fhop [:tostr [/ip dhcp-client get ([/ip dhcp-client find]->0) gateway]] } on-error={} }
:put ("  total routes: " . [:len [/ip route find]])
:do { /ip dhcp-client print detail } on-error={ :put "  (no dhcp-client - static WAN)" }
:do { :set netwDown [:len [/tool netwatch find where status="down"]] } on-error={}
:do { :if ([:len [/tool netwatch find]]=0) do={ :put "  netwatch: (none configured)" } else={ :foreach w in=[/tool netwatch find] do={ :put ("  netwatch " . [/tool netwatch get $w host] . "  status=" . [/tool netwatch get $w status] . "  since=" . [/tool netwatch get $w since]) } } } on-error={}

:put ""
[$prog "C2 first-hop ping"]
:put "===== C2  FIRST HOP (true next-hop / site uplink) ====="
:if ([:len $fhop]=0) do={ :set fhop $wangw }
:if ([:len $fhop]>0) do={
  :put (">>> ping first hop " . $fhop . "  (route gw was " . $wangw . " - on Eleven recursive-route configs that is a public IP, immediate-gw is the real uplink):")
  :do { /ping $fhop count=5 } on-error={ :put "  (first hop not pingable as IP)" }
  :do { :set gwLoss (3 - [/ping $fhop count=3]) } on-error={}
} else={ :put "  (no active default route!)" }

:put ""
:local stC2 "PASS"; :if ($gwLoss>0) do={ :set stC2 "FLAG" }
[$prog ("C2 first-hop " . $stC2 . " (loss " . $gwLoss . "/3)")]
[$prog "C3 internet anchors + MTU + traceroute (~45s)"]
:put "===== C3  INTERNET ANCHORS (loss / rtt / MTU / per-hop) ====="
:foreach a in=$ANCHORS do={ :put (">>> ping " . $a . ":"); /ping $a count=10; :do { :set wanLoss ($wanLoss + (3 - [/ping $a count=3])) } on-error={ :set wanLoss ($wanLoss+3) } }
:do { :set mtuRx [/ping [:pick $ANCHORS 0] count=4 size=1472 do-not-fragment] } on-error={}
:put ("MTU-DF 1472+28=1500 : received " . $mtuRx . "/4   (0 while small pings pass = PMTU black hole on WAN)")
:put (">>> traceroute to " . [:pick $ANCHORS 0] . " (count=1, 8 hops max; progressive render - read the LAST table):")
:do { /tool traceroute [:pick $ANCHORS 0] count=1 timeout=1s max-hops=8 } on-error={ :put "  (traceroute n/a on this build)" }

:put ""
:local stC3 "PASS"; :if ((($wanLoss>0)) or (($mtuRx=0))) do={ :set stC3 "FLAG" }
[$prog ("C3 anchors " . $stC3 . " (loss " . $wanLoss . ", mtu-df rx " . $mtuRx . "/4)")]
[$prog "C4 dns upstream sweep + daemon timing"]
:put "===== C4  DNS UPSTREAM SWEEP (checkDNS method: each upstream, retry once; PASS = under 2s + 0 fails) ====="
:local srvmap [:toarray ""]
:do { :foreach s in=[:toarray [/ip dns get servers]] do={ :set ($srvmap->[:tostr $s]) "static" } } on-error={}
:do { :foreach s in=[:toarray [/ip dns get dynamic-servers]] do={ :if ([:typeof ($srvmap->[:tostr $s])]="nothing") do={ :set ($srvmap->[:tostr $s]) "dynamic" } } } on-error={}
:foreach a in=$ANCHORS do={ :if ([:typeof ($srvmap->$a)]="nothing") do={ :set ($srvmap->$a) "public-ref" } }
:foreach sip,typ in=$srvmap do={
  :local fails 0; :local retries 0
  :local t1 [:timestamp]
  :foreach d in=$CANARY do={
    :do { [:resolve $d server=$sip] } on-error={
      :set retries ($retries+1)
      :do { [:resolve $d server=$sip] } on-error={ :set fails ($fails+1) }
    }
  }
  :local ms (([:timestamp]-$t1)/1ms)
  :local vv "PASS"
  :if (($fails>0) or ($ms>2000)) do={ :set vv "FAIL"; :set dnsSrvBad ($dnsSrvBad+1) }
  :put ("  " . $vv . "  " . $sip . " (" . $typ . ")  " . [:len $CANARY] . " canaries in " . $ms . "ms  retries=" . $retries . "  fails=" . $fails)
}
:put ">>> if a configured upstream FAILS here, run checkDNS.rsc for guided prune/backfill remediation"
:put ""
:put ">>> LOCAL daemon pass 1 (as-found cache state):"
:foreach d in=$PROBES do={ :local t1 [:timestamp]; :do { :local ip [:resolve $d]; :put ("  1 " . $d . " -> " . $ip . "  " . (([:timestamp]-$t1)/1ms) . "ms") } on-error={ :put ("  1 " . $d . " -> FAIL") } }
:put ">>> LOCAL daemon pass 2 (warm; healthy = 0-1ms; STILL slow = daemon/CPU-bound on this box):"
:foreach d in=$PROBES do={ :local t1 [:timestamp]; :do { :local ip [:resolve $d]; :local ms (([:timestamp]-$t1)/1ms); :if ($ms>$warmMs) do={ :set warmMs $ms }; :if ($ms>20) do={ :set warmSlow ($warmSlow+1) }; :put ("  2 " . $d . " -> " . $ip . "  " . $ms . "ms") } on-error={ :put ("  2 " . $d . " -> FAIL") } }
:local stC4 "PASS"; :if ((($dnsSrvBad>0)) or (($warmSlow>2))) do={ :set stC4 "FLAG" }
[$prog ("C4 dns " . $stC4 . " (bad upstreams " . $dnsSrvBad . ", warm max " . $warmMs . "ms)")]

:put ""
[$prog "C5 L7 fetch tests (15s cap each)"]
:put "===== C5  L7 OUTBOUND (tcp/80 + tcp/443 + TLS through the real WAN path) ====="
:put ">>> fetches ran in a parallel depth-1 job started at import time (fetch hangs in depth-2 jobs - field-proven)"
:global hcF1 ; :global hcF2 ; :global hcF3 ; :global hcFjid
:local fw 0
:while (($fw<30) and (((($hcF1="pending")) or (($hcF2="pending")) or (($hcF3="pending"))))) do={ :delay 1s; :set fw ($fw+1) }
:put ("  http  msftconnecttest.com : " . $hcF1)
:put ("  https gstatic generate204 : " . $hcF2)
:put ("  https portal root         : " . $hcF3)
:if ($hcF1="pending") do={ :set fetchFail ($fetchFail+1); :put "  ! http fetch never finished - upstream port-80 blackhole signal" }
:if ($hcF2="pending") do={ :set fetchFail ($fetchFail+1); :put "  ! https fetch never finished - upstream port-443 blackhole signal" }
:do { :if ([:typeof [:find [:tostr $hcF1] "FAIL"]]="num") do={ :set fetchFail ($fetchFail+1) } } on-error={}
:do { :if ([:typeof [:find [:tostr $hcF2] "FAIL"]]="num") do={ :set fetchFail ($fetchFail+1) } } on-error={}
:if (((($hcF1="pending")) or (($hcF2="pending")) or (($hcF3="pending")))) do={ :do { /system script job remove $hcFjid } on-error={} ; :put "  (wedged fetch job killed - report continues)" }
:do { /system script environment remove [find where name~"^hcF"] } on-error={}
:local stC5 "PASS"; :if ($fetchFail>0) do={ :set stC5 "FLAG" }
[$prog ("C5 L7 fetch " . $stC5 . " (fails/timeouts " . $fetchFail . ")")]

:put ""
[$prog "C6 radius monitor"]
:put "===== C6  RADIUS (cloud auth reachability) ====="
:do { :foreach rs in=[/radius find] do={
  :local m [/radius monitor $rs once as-value]
  :local to [$gv $m "timeouts"]
  :do { :set radTimeout ($radTimeout + $to) } on-error={}
  :do { :set radOk ($radOk + [$gv $m "accepts"] + [$gv $m "rejects"]) } on-error={}
  :put ("  " . [/radius get $rs address] . "  accepts=" . [$gv $m "accepts"] . " rejects=" . [$gv $m "rejects"] . " timeouts=" . $to . " rtt=" . [$gv $m "last-request-rtt"] . " pending=" . [$gv $m "pending"])
} } on-error={ :put "  (radius monitor n/a)" }
:put ("  radius servers configured: " . [:len [/radius find]])
:local stC6 "PASS"; :if ($radTimeout>10) do={ :set stC6 "FLAG" }
[$prog ("C6 radius " . $stC6 . " (timeouts " . $radTimeout . ")")]

:put ""
[$prog "C7 vrrp/ha"]
:put "===== C7  VRRP / HA ====="
:local nv [:len [/interface vrrp find]]
:if ($nv=0) do={ :put "  (no VRRP configured)" } else={
  :foreach v in=[/interface vrrp find] do={
    :local vrun "-"; :do { :set vrun [/interface vrrp get $v running] } on-error={}
    :put ("  VRRP " . [/interface vrrp get $v name] . "  priority=" . [/interface vrrp get $v priority] . "  disabled=" . [/interface vrrp get $v disabled] . "  running(master)=" . $vrun)
    :do { /interface vrrp monitor $v once } on-error={}
  }
  :put "  (run this healthcheck on BOTH HA members and compare)"
}
:do { :set vrrpLog [:len [/log find where topics~"vrrp"]] } on-error={}
:put ("  vrrp log lines in buffer: " . $vrrpLog . "  (high = flap - check same-IP WAN/HA design)")

:put ""
[$prog "C8 wan/upstream log scan"]
:put "===== C8  WAN/UPSTREAM LOG SCAN ====="
/log print where topics~"dns" or topics~"radius" or topics~"ntp" or topics~"vrrp"

:put ""
[$prog "D control-plane pcaps (sync-aware; may wait up to 70s)"]
:put "########## D  CONTROL-PLANE PCAPS (guest bridge, single-interface bind) ##########"
:local guestif ""
:local bestn -1
:do { :foreach h in=[/ip hotspot find] do={
  :local hifc [:tostr [/ip hotspot get $h interface]]
  :local cnt 0
  :do { :foreach sx in=[/ip dhcp-server find where interface=$hifc] do={ :set cnt ($cnt + [:len [/ip dhcp-server lease find where status=bound and server=[/ip dhcp-server get $sx name]]]) } } on-error={}
  :if ($cnt>$bestn) do={ :set bestn $cnt; :set guestif $hifc }
} } on-error={}
:if ([:len $guestif]=0) do={ :do { :set guestif [:tostr [/interface bridge get ([/interface bridge find]->0) name]] } on-error={} }
:if ([:len $guestif]>0) do={ :put ("  guest interface picked: " . $guestif . "  (" . $bestn . " bound leases - busiest hotspot wins)") }
:local fhdd [/system resource get free-hdd-space]
:local plim 8000
:if ($fhdd<20000000) do={ :set plim 2000 }
:if ($DOPCAP=false) do={ :put "  (pcap disabled by DOPCAP toggle)" } else={
:if ($cpuMax>75) do={ :put ("  SKIPPED - cpu peaked " . $cpuMax . "% during sampling; sniffing would make it worse") } else={
:if ($fhdd<5000000) do={ :put "  SKIPPED - under 5MB free disk" } else={
:if ([:len $guestif]=0) do={ :put "  SKIPPED - no hotspot/bridge interface discovered" } else={
  :do {
    :local sid [/system scheduler find where name="sync"]
    :if ([:len $sid]>0) do={
      :put "  ElevenOS sync scheduler present - it STOPS a running sniffer, so waiting for its next tick (max 70s)..."
      [$prog "D waiting for ElevenOS sync tick before pcaps (max 70s)"]
      :local rc0 [/system scheduler get ($sid->0) run-count]
      :local wtd 0
      :while (($wtd<70) and ([/system scheduler get ($sid->0) run-count]=$rc0)) do={ :delay 2s; :set wtd ($wtd+2) }
      :if ([/system scheduler get ($sid->0) run-count]=$rc0) do={ :put ("  sync did not tick within " . $wtd . "s - proceeding anyway") } else={ :put ("  sync ticked (waited " . $wtd . "s) - settling 3s, then ~45s of captures fit the ~60s gap"); :delay 3s }
    }
  } on-error={ :put "  (sync run-count not readable - capturing without alignment)" }
  :do {
    /tool sniffer stop
    :local pfilter "53"
    :do { :local drp [:tostr [/ip firewall nat get ([find where action=redirect protocol=udp dst-port=53]->0) to-ports]]; :if ([:len $drp]>0) do={ :set pfilter ("53," . $drp) } } on-error={}
    :put ("  dns capture ports: " . $pfilter . "  (53 + hotspot redirect to-port; guest queries appear post-NAT on the bridge)")
    :do { /tool sniffer set file-name=healthcheck-dns.pcap file-limit=$plim filter-interface=$guestif filter-mac-address="" filter-ip-address="" filter-mac-protocol="" filter-ip-protocol=udp filter-port=$pfilter filter-stream=no } on-error={ /tool sniffer set file-name=healthcheck-dns.pcap file-limit=$plim filter-interface=$guestif filter-mac-address="" filter-ip-address="" filter-mac-protocol="" filter-ip-protocol=udp filter-port=53 filter-stream=no }
    /tool sniffer start
    :put ("  capturing udp/53 on " . $guestif . " for " . $DNSPCAPSECS . "s -> healthcheck-dns.pcap")
    :local killed false
    :local elap 0
    :while (($elap<$DNSPCAPSECS) and ($killed=false)) do={ :delay 2s; :set elap ($elap+2); :do { :if ([/tool sniffer get running]=false) do={ :set killed true } } on-error={} }
    :do { /tool sniffer stop } on-error={}
    :local psz "-"; :do { :set psz [/file get ([/file find where name~"healthcheck-dns.pcap"]->0) size] } on-error={}
    :if ($killed=true) do={ :put ("  ! dns capture STOPPED EARLY at ~" . $elap . "s (usually the ElevenOS sync scheduler killing the sniffer) - file-size=" . $psz) } else={ :put ("  dns capture done, file-size=" . $psz . " bytes") }
    :do { :if ($psz<200) do={ :put ("  (header-only file = nothing crossed " . $guestif . " during the window - idle or wrong bridge)") } } on-error={}
    [$prog ("D dns-pcap killed=" . $killed . " size=" . $psz)]
  } on-error={ :put "  (dns pcap failed - continuing)" }
  :do {
    /tool sniffer set file-name=healthcheck-arp.pcap file-limit=$plim filter-interface=$guestif filter-ip-protocol="" filter-port="" filter-mac-protocol=arp filter-stream=no
    /tool sniffer start
    :put ("  capturing ARP on " . $guestif . " for " . $ARPPCAPSECS . "s -> healthcheck-arp.pcap")
    :local killed2 false
    :local elap2 0
    :while (($elap2<$ARPPCAPSECS) and ($killed2=false)) do={ :delay 2s; :set elap2 ($elap2+2); :do { :if ([/tool sniffer get running]=false) do={ :set killed2 true } } on-error={} }
    :do { /tool sniffer stop } on-error={}
    :local psz2 "-"; :do { :set psz2 [/file get ([/file find where name~"healthcheck-arp.pcap"]->0) size] } on-error={}
    :if ($killed2=true) do={ :put ("  ! arp capture STOPPED EARLY at ~" . $elap2 . "s (usually the ElevenOS sync scheduler killing the sniffer) - file-size=" . $psz2) } else={ :put ("  arp capture done, file-size=" . $psz2 . " bytes") }
    :do { :if ($psz2<200) do={ :put ("  (header-only file = nothing crossed " . $guestif . " during the window - idle or wrong bridge)") } } on-error={}
    [$prog ("D arp-pcap killed=" . $killed2 . " size=" . $psz2)]
    /tool sniffer set filter-mac-protocol="" filter-interface=all file-name=""
  } on-error={ :put "  (arp pcap failed - continuing)" }
  :put "  NOTE: single-interface bind avoids the Nx duplicate-frame artifact."
  :put "  KNOWN BEHAVIOUR: the ElevenOS sync scheduler STOPS a running sniffer when they overlap;"
  :put "  this script waits for a sync tick first so the ~45s of captures fit the ~60s gap."
  :put "  If a capture still reports STOPPED EARLY: an engineer can temporarily disable the sync"
  :put "  scheduler, re-run just the pcaps, then RE-ENABLE it (see data-collection.md - never leave it off)."
  :put "  For a PER-CLIENT flow pcap (full join->portal of one test device) use the interactive"
  :put "  flow-capture companion script - it needs a device MAC and a human rejoining the SSID."
} } } }

:put ""
[$prog "VERDICT computing fault-domain summary"]
:put "############ FAULT-DOMAIN VERDICT ############"
:put "(signals, not proof - correlate with symptom timeline + client-side pcap/HAR before closing)"
:put ""
:put "--- INSIDE THE BOX ---"
:if ($cpuMax>50) do={ :set flags ($flags+1); :put ("  ! CPU peaked " . $cpuMax . "% (over 50) - resource pressure") }
:if (($memPct<20) and ($memPct>0)) do={ :set flags ($flags+1); :put ("  ! memory only " . $memPct . "% free") }
:do { :if ([/system ntp client get enabled]=false) do={ :put "  note: NTP client disabled - clock drift will eventually break TLS (portal certs, cloud sync)" } } on-error={}
:if ($kaBad>0) do={ :set flags ($flags+1); :put "  ! timing: keepalive-timeout >= dhcp lease (sessions can outlive leases; usually masked where mac-cookie login is enabled, weigh against symptom)" }
:if ($warmSlow>2) do={ :set flags ($flags+1); :put ("  ! resolver WARM pass slow on " . $warmSlow . " of 10 probes (max " . $warmMs . "ms) - daemon/CPU/upstream-bound ON this box") } else={ :if ($warmSlow>0) do={ :put ("  ok-ish: warm max " . $warmMs . "ms on " . $warmSlow . " probe(s) - isolated TTL re-resolve at WAN cost, NOT daemon latency") } else={ :put ("  ok: resolver fast (warm max " . $warmMs . "ms) - internal DNS is NOT the bottleneck") } }
:if ($cachePct>90) do={ :set flags ($flags+1); :put ("  ! DNS cache " . $cachePct . "% used - saturation (raise cache-size to 4096KiB, max-ttl 1d)") }
:if ($cacheFullLog>0) do={ :set flags ($flags+1); :put ("  ! " . $cacheFullLog . " cache-full log lines - resolver dropping answers (smoking gun)") }
:if ($zeroc>50) do={ :set flags ($flags+1); :put ("  ! " . $zeroc . " blackhole 0.0.0.0 DNS cache entries (DEF-001/002)") }
:if ($ctPct>80) do={ :set flags ($flags+1); :put ("  ! conntrack " . $ctPct . "% of max - connection storm / exhaustion") }
:if ($staticDns>20) do={ :set flags ($flags+1); :put ("  ! " . $staticDns . " static DNS entries - check none shadow portal/walled-garden names") }
:put ""
:put "--- OUTSIDE: LAN / WIRELESS / CLIENT SIDE ---"
:if ($jnpFresh>0) do={ :set flags ($flags+1); :put ("  ! " . $jnpFresh . " FRESH joined-but-no-portal clients (raw " . $jnp . " incl stale long-lease entries) - portal not firing (CNA/VPN, walled-garden, redirect, or wireless)") } else={ :if ($jnp>0) do={ :put ("  note: all " . $jnp . " joined-but-no-portal entries are STALE leases (none seen under 30m) - churn residue, not a live portal fault") } }
:if ($ghost>0) do={ :set flags ($flags+1); :put ("  ! " . $ghost . " ghosting/IP-theft entries - AP proxy-ARP (DEF-008) or rogue static IPs") }
:if ($dhcpConflict>3) do={ :set flags ($flags+1); :put ("  ! " . $dhcpConflict . " DHCP conflicts - rogue devices / proxy-ARP / IoT churn (over 10 = critical)") }
:if (($arpIncPct>5) and ($arpTotal>49)) do={ :set flags ($flags+1); :put ("  ! ARP incomplete " . $arpIncPct . "% (over 5, table of " . $arpTotal . ") - L2 reachability / churn") }
:if (($ratioFresh>115) and ($nbFresh>0)) do={ :set flags ($flags+1); :put ("  ! FRESH session/lease ratio " . $ratioFresh . "% (over 115) - session leak / stale actives") }
:if (($ratioFresh<40) and ($nbFresh>19)) do={ :set flags ($flags+1); :put ("  ! FRESH session/lease ratio only " . $ratioFresh . "% with " . $nbFresh . " leases seen under 30m - many live joiners, few authenticated: portal delivery problem") }
:if ($l1delta>0) do={ :set flags ($flags+1); :put ("  ! interface errors INCREASED during the 10s window (delta=" . $l1delta . ") - live L1 fault, see B2 for which port") }
:if ($movedLog>0) do={ :set flags ($flags+1); :put ("  ! " . $movedLog . " loop/mac-move/own-address log lines - L2 instability") }
:if ($stpOff>0) do={ :put ("  note: " . $stpOff . " bridge(s) with protocol-mode=none - no loop protection at gateway (design-dependent)") }
:if ($nbrLossy>0) do={ :set flags ($flags+1); :put ("  ! " . $nbrLossy . " LAN infra neighbour(s) PARTIALLY answering ping - degraded/overloaded switch-AP path") }
:if ($nbrSilent>0) do={ :put ("  note: " . $nbrSilent . " neighbour(s) fully silent to ping - often just ICMP-filtered management IPs, verify another way") }
:if ($nbrSlowMs>100) do={ :set flags ($flags+1); :put ("  ! slowest LAN infra neighbour " . $nbrSlowIp . " avg " . $nbrSlowMs . "ms (over 100) - loaded core/backhaul INSIDE the site LAN") }
:if ($cliRx>0) do={ :local cavg ($cliSum/$cliRx); :if ($cavg>100) do={ :set flags ($flags+1); :put ("  ! guest-device RTT avg " . $cavg . "ms (over 100) - WIRELESS/AP path latency, not this box") } else={ :put ("  ok: sampled guest RTT avg " . $cavg . "ms - wired+wireless path to clients looks sane") } }
:if (($cliTx>0) and ($cliRx=0)) do={ :put "  note: 0 client ping replies - could be all-asleep devices; treat as unknown, not proof" }
:if ($flapBurn>0) do={ :set flags ($flags+1); :put ("  ! " . $flapBurn . " burned-in-OUI MAC(s) each holding multiple IPs (B11) - IoT/thermostats/APs likely STILL on the guest VLAN; move to an IoT VLAN/SSID (B11 lists host-names)") }
:if ($flapRnd>5) do={ :set flags ($flags+1); :put ("  ! " . $flapRnd . " randomized-MAC guest device(s) holding multiple IPs (B11) - re-association churn (airtime/roaming); correlate with B9 RTT and client-side retry rate") }
:if ($dhcpFlapLog>50) do={ :set flags ($flags+1); :put ("  ! " . $dhcpFlapLog . " DHCP assign/deassign/offer log lines (B11) - lease thrash: clients not completing or not holding DORA") }
:put ""
:put "--- OUTSIDE: WAN / UPSTREAM / CLOUD ---"
:if ($gwLoss>0) do={ :set flags ($flags+1); :put ("  ! loss pinging the FIRST HOP (" . $gwLoss . "/3) - site uplink / WAN edge, not internet") }
:if (($gwLoss=0) and ($wanLoss>0)) do={ :set flags ($flags+1); :put ("  ! first hop clean but anchor loss (" . $wanLoss . "/6 sampled) - upstream/ISP beyond the site edge") }
:if (($wanLoss=0) and ($gwLoss=0)) do={ :put "  ok: WAN 0 loss to first hop and public anchors (sampled)" }
:if ($mtuRx=0) do={ :set flags ($flags+1); :put "  ! 1500-byte DF pings all dropped - PMTU black hole / reduced-MTU WAN (VPN-wrapped uplink?)" }
:if ($dnsSrvBad>0) do={ :set flags ($flags+1); :put ("  ! " . $dnsSrvBad . " DNS upstream(s) FAILED the checkDNS sweep - dead/slow site or ISP resolvers (Movenpick 48834 class)") } else={ :put "  ok: all DNS upstreams passed the sweep" }
:if ($fetchFail>0) do={ :set flags ($flags+1); :put ("  ! " . $fetchFail . " L7 fetch test(s) failed/timed out - port 80/443 or TLS blocked/filtered upstream (portal-root non-200 not counted)") }
:if ($radTimeout>10) do={ :set flags ($flags+1); :put ("  ! RADIUS timeouts total " . $radTimeout . " (over 10) - cloud-auth reachability") } else={ :if (($radOk=0) and ($radTimeout>0)) do={ :put ("  note: RADIUS counters show 0 accepts/rejects but " . $radTimeout . " timeouts - no live auth traffic to judge by; verify during an incident window") } else={ :put "  ok: RADIUS responding" } }
:if ($netwDown>0) do={ :set flags ($flags+1); :put ("  ! " . $netwDown . " netwatch probe(s) DOWN right now") }
:if ($vrrpLog>10) do={ :set flags ($flags+1); :put ("  ! " . $vrrpLog . " VRRP log lines - HA flap; check same-IP WAN/HA design and run this on the peer") }
:put ""
:if (($warmMs<20) and (($jnp>0) or ($ghost>0) or ($dhcpConflict>3) or ($flapMultiMac>5))) do={ :put "  => resolver fast but portal/churn signals present: client-observed latency most likely lives in the WIRELESS/AP path, not this gateway" }
:if ($flags=0) do={ :put "  => NO RED FLAGS on this box at capture time. Fault is likely intermittent, client-side, or in a domain this box cannot see (AP/controller RF, upstream content filtering). Re-run DURING an incident window and pair with a client-side pcap + HAR." }
:put ""
[$prog ("VERDICT done - " . $flags . " red flag(s)")]
:put "NEXT: send this .txt + healthcheck-dns.pcap + healthcheck-arp.pcap (+ client HAR if web symptom)"
:put "      to escalation for /hsia-diagnose analysis. Re-run during incident for before/after diffing."

:put ""
[$prog "Z config export (long output - final section)"]
:put "########## Z  FULL CONFIG EXPORT (sensitive values hidden) ##########"
:do { /export hide-sensitive } on-error={ /export }

:put ""
[$prog "COMPLETE - full report written, pull the files from Files"]
:put "############ END OF GW-HEALTHCHECK REPORT ############"
}

:put ""
:put ("[gw-healthcheck] STARTED as a background job -> " . $fname . ".txt")
:put "[gw-healthcheck] Wait ~5 minutes (up to ~10 if DNS upstreams are dead), do NOT re-import meanwhile."
:put ("[gw-healthcheck] Then: Files -> " . $fname . ".txt (+ healthcheck-dns.pcap / healthcheck-arp.pcap) -> drag out and send back.")
:put "[gw-healthcheck] The report is complete only when its last line reads: END OF GW-HEALTHCHECK REPORT"
:put "[gw-healthcheck] LIVE PROGRESS: open the Winbox Log window, or run:"
:put "[gw-healthcheck]   /log print follow-only where message~\"hc:\""
:put "[gw-healthcheck] One hc: line per section with PASS/FLAG as tests finish; 'hc: COMPLETE' = done."
:put ""
