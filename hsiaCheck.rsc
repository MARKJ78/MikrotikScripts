##############################################################################
# hsiaCheck.rsc -- Eleven Software HSIA gateway live health audit
#
# Mirrors the offline diagnostics scoring (mikrotik-diagnostics.md):
#   timing 25, system 15, dhcp 15, session 15, network 15, radius 10, dns 5.
# Plus informational checks (AAAoff bypass, sync scheduler, walled-garden
# anti-pattern, VRRP) that print warnings without affecting the score.
#
# Run live on a hotspot gateway:
#   /tool fetch url="https://raw.githubusercontent.com/MARKJ78/MikrotikScripts/master/hsiaCheck.rsc" mode=https
#   /import hsiaCheck.rsc
#
# Toggle individual sections below to scope a customer-call audit.
##############################################################################

# ---- toggles --------------------------------------------------------------
:local runTiming  true
:local runSystem  true
:local runDhcp    true
:local runSession true
:local runIface   true
:local runRadius  true
:local runDns     true
:local runAaa     true
:local runWg      true
:local runVrrp    true

:local score 100
:local summary ({})

:put "###############################################################"
:put "# hsiaCheck.rsc -- live HSIA gateway audit"
:put "# Started: $[/system clock get date] $[/system clock get time]"
:put "# Device:  $[/system identity get name]  RouterOS $[/system resource get version]"
:put "###############################################################"
:put ""

# === 1. Timing config + MAC cookies (weight 25) ============================
# Critical rule from mikrotik-diagnostics.md: keepalive < lease, MAC cookies
# present. keepalive >= lease is DEF-004. Idle > keepalive/2 also flagged.
:if ($runTiming) do={
    :put "#### 1. Timing config + MAC cookies (weight 25)"
    :local status "PASS"
    :local detail ""
    :local minLease 0
    :foreach d in=[/ip dhcp-server find] do={
        :local lt 0
        :do { :set lt [:tonum [/ip dhcp-server get $d lease-time]] } on-error={}
        :if ($lt > 0 and ($minLease = 0 or $lt < $minLease)) do={ :set minLease $lt }
    }
    :foreach p in=[/ip hotspot profile find] do={
        :local pname [/ip hotspot profile get $p name]
        :local ka 0
        :local idle 0
        :do { :set ka   [:tonum [/ip hotspot profile get $p keepalive-timeout]] } on-error={}
        :do { :set idle [:tonum [/ip hotspot profile get $p idle-timeout]] } on-error={}
        :put "   profile $pname: keepalive=$ka idle=$idle (sec), min-lease=$minLease s"
        :if ($minLease > 0 and $ka > 0 and $ka >= $minLease) do={
            :set status "FAIL"
            :set detail ($detail . $pname . ": keepalive>=lease (DEF-004); ")
        } else={
            :if ($minLease > 0 and $ka > 0 and ($minLease - $ka) < 7200) do={
                :if ($status = "PASS") do={ :set status "WARN" }
                :set detail ($detail . $pname . ": <2h margin; ")
            }
        }
        :if ($idle > 0 and $ka > 0 and $idle > ($ka / 2)) do={
            :if ($status = "PASS") do={ :set status "WARN" }
            :set detail ($detail . $pname . ": idle>keepalive/2; ")
        }
    }
    :local cookies 0
    :do { :set cookies [/ip hotspot cookie print count-only] } on-error={}
    :if ($cookies = 0) do={
        :if ($status = "PASS") do={ :set status "WARN" }
        :set detail ($detail . "no MAC cookies present; ")
    }
    :if ([:len $detail] = 0) do={ :set detail "keepalive<lease, MAC cookies present" }
    :put "## $status: timing -- $detail"
    :if ($status = "FAIL") do={ :set score ($score - 25) }
    :if ($status = "WARN") do={ :set score ($score - 12) }
    :set ($summary->[:len $summary]) "$status timing"
    :put ""
}

# === 2. System hardware (weight 15) ========================================
# CPU<20 mem-free>50 disk-free>50MB healthy; CPU>50 mem<20 bad-blocks critical.
:if ($runSystem) do={
    :put "#### 2. System hardware (weight 15)"
    :local cpu [/system resource get cpu-load]
    :local freem [/system resource get free-memory]
    :local totm  [/system resource get total-memory]
    :local memPct 0
    :if ($totm > 0) do={ :set memPct (($freem * 100) / $totm) }
    :local freedisk [/system resource get free-hdd-space]
    :local bad 0
    :do { :set bad [/system resource get bad-blocks] } on-error={}
    :local detail "cpu=$cpu%, mem-free=$memPct%, disk-free=$freedisk B, bad-blocks=$bad"
    :local status "PASS"
    :if ($cpu > 50 or $memPct < 20 or $freedisk < 10485760 or $bad > 0) do={
        :set status "FAIL"; :set score ($score - 15)
    } else={
        :if ($cpu > 20 or $memPct < 50 or $freedisk < 52428800) do={
            :set status "WARN"; :set score ($score - 7)
        }
    }
    :put "## $status: system -- $detail"
    :set ($summary->[:len $summary]) "$status system"
    :put ""
}

# === 3. DHCP server (weight 15) ============================================
:if ($runDhcp) do={
    :put "#### 3. DHCP server (weight 15)"
    :local conflicts 0
    :local bound 0
    :do { :set conflicts [/ip dhcp-server lease print count-only where status=conflict] } on-error={}
    :do { :set bound     [/ip dhcp-server lease print count-only where status=bound]    } on-error={}
    :local detail "bound=$bound, conflicts=$conflicts"
    :local status "PASS"
    :if ($conflicts > 10) do={
        :set status "FAIL"; :set score ($score - 15)
        :set detail ($detail . " -- check DEF-008 (ARP proxy interference)")
    } else={
        :if ($conflicts >= 3) do={ :set status "WARN"; :set score ($score - 7) }
    }
    :put "## $status: dhcp -- $detail"
    :set ($summary->[:len $summary]) "$status dhcp"
    :put ""
}

# === 4. Session / lease ratio (weight 15) ==================================
# 0.65-1.04 healthy; 1.04-1.08 marginal; >1.08 warn; >1.15 critical
# (with MAC cookies, ratio 0.65-0.75 is the typical healthy band)
:if ($runSession) do={
    :put "#### 4. Session / lease ratio (weight 15)"
    :local active 0
    :local bound 0
    :do { :set active [/ip hotspot active print count-only]                          } on-error={}
    :do { :set bound  [/ip dhcp-server lease print count-only where status=bound]    } on-error={}
    :local ratio 0
    :if ($bound > 0) do={ :set ratio (($active * 100) / $bound) }
    :local detail "active=$active, bound=$bound, ratio=$ratio% (target 65-104%)"
    :local status "PASS"
    :if ($ratio > 115) do={
        :set status "FAIL"; :set score ($score - 15)
        :set detail ($detail . " -- DEF-003/DEF-004 candidate")
    } else={
        :if ($ratio > 108) do={
            :set status "WARN"; :set score ($score - 10)
        } else={
            :if ($ratio > 104) do={ :set status "WARN"; :set score ($score - 5) }
        }
    }
    :put "## $status: session -- $detail"
    :set ($summary->[:len $summary]) "$status session"
    :put ""
}

# === 5. Network interfaces (weight 15) =====================================
# Critical = bridge down, OR ether/sfp that previously carried traffic now down.
# Errors >100 warn, >1000 stronger warn (no FAIL bucket per the doc).
:if ($runIface) do={
    :put "#### 5. Network interfaces (weight 15)"
    :local downCrit 0
    :local downList ""
    :local errSum 0
    :foreach i in=[/interface find where !disabled] do={
        :local iname [/interface get $i name]
        :local itype [/interface get $i type]
        :local irun  [/interface get $i running]
        :local irx 0
        :do { :set irx [/interface get $i rx-byte] } on-error={}
        :if (!$irun and ($itype = "bridge" or $irx > 0)) do={
            :set downCrit ($downCrit + 1)
            :set downList ($downList . $iname . " ")
        }
        :do {
            :local rxe [/interface get $i rx-error]
            :local txe [/interface get $i tx-error]
            :set errSum ($errSum + $rxe + $txe)
        } on-error={}
    }
    :local detail "down-critical=$downCrit ($downList), error-counters=$errSum"
    :local status "PASS"
    :if ($downCrit > 0) do={
        :set status "FAIL"; :set score ($score - 15)
    } else={
        :if ($errSum > 1000) do={
            :set status "WARN"; :set score ($score - 10)
        } else={
            :if ($errSum > 100) do={ :set status "WARN"; :set score ($score - 5) }
        }
    }
    :put "## $status: interfaces -- $detail"
    :set ($summary->[:len $summary]) "$status interfaces"
    :put ""
}

# === 6. RADIUS auth (weight 10) ============================================
:if ($runRadius) do={
    :put "#### 6. RADIUS auth (weight 10)"
    :local servers 0
    :local timeouts 0
    :local rejects 0
    :do { :set servers  [/radius print count-only] } on-error={}
    :do { :set timeouts [/log print count-only where topics~"radius" and message~"timeout"] } on-error={}
    :do { :set rejects  [/log print count-only where topics~"radius" and message~"reject"]  } on-error={}
    :local detail "servers=$servers, log timeouts=$timeouts, log rejects=$rejects"
    :local status "PASS"
    :if ($servers = 0) do={
        :set status "FAIL"; :set score ($score - 10)
        :set detail ($detail . " -- no RADIUS servers configured")
    } else={
        :if ($timeouts > 10) do={
            :set status "FAIL"; :set score ($score - 10)
        } else={
            :if ($timeouts > 0 or $rejects > 5) do={
                :set status "WARN"; :set score ($score - 5)
            }
        }
    }
    :put "## $status: radius -- $detail"
    :set ($summary->[:len $summary]) "$status radius"
    :put ""
}

# === 7. DNS cache health (weight 5) ========================================
# #48834 / Apple-CNA pattern: cache full + small cache-size + long max-ttl.
:if ($runDns) do={
    :put "#### 7. DNS cache (weight 5)"
    :local cacheFull 0
    :do { :set cacheFull [/log print count-only where message~"cache full"] } on-error={}
    :local cacheSize 0
    :do { :set cacheSize [/ip dns get cache-size] } on-error={}
    :local detail "cache-size=$cacheSize KiB, cache-full log lines=$cacheFull"
    :local status "PASS"
    :if ($cacheFull > 10) do={
        :set status "FAIL"; :set score ($score - 5)
        :set detail ($detail . " -- DNS cache saturated (#48834 Apple-CNA pattern)")
    } else={
        :if ($cacheFull > 0 or $cacheSize < 4096) do={
            :set status "WARN"; :set score ($score - 2)
            :if ($cacheSize < 4096) do={
                :set detail ($detail . " -- recommend cache-size=4096KiB cache-max-ttl=1d for hotel scale")
            }
        }
    }
    :put "## $status: dns -- $detail"
    :set ($summary->[:len $summary]) "$status dns"
    :put ""
}

# === Informational: AAA bypass + sync scheduler (no score) =================
# AAAoff binding + sync disabled = portal toggle silently fails.
:if ($runAaa) do={
    :put "#### Informational: AAA bypass + sync scheduler"
    :local aaa 0
    :do { :set aaa [/ip hotspot ip-binding print count-only where comment~"AAAoff"] } on-error={}
    :local sd "?"
    :do { :set sd [/system scheduler get [find name=sync] disabled] } on-error={ :set sd "no-scheduler" }
    :local status "PASS"
    :local detail "AAAoff bindings=$aaa, sync disabled=$sd"
    :if ($aaa > 0 and $sd = true) do={
        :set status "FAIL"
        :set detail ($detail . " -- AAAoff active AND sync disabled: portal toggle WILL NOT reach gateway")
    } else={
        :if ($aaa > 0) do={
            :set status "WARN"
            :set detail ($detail . " -- gateway in AAA-off bypass")
        }
        :if ($sd = true) do={
            :set status "WARN"
            :set detail ($detail . " -- sync scheduler disabled, ElevenOS pushes blocked")
        }
    }
    :put "## $status: aaa/sync -- $detail (informational, score unchanged)"
    :set ($summary->[:len $summary]) "$status aaa/sync (info)"
    :put ""
}

# === Informational: Walled garden anti-pattern (DEF-010, no score) =========
:if ($runWg) do={
    :put "#### Informational: Walled garden anti-pattern (DEF-010)"
    :local wg1 0
    :local wg2 0
    :do { :set wg1 [/ip hotspot walled-garden print count-only where dst-host~"msftconnecttest"] } on-error={}
    :do { :set wg2 [/ip hotspot walled-garden print count-only where dst-host~"msftncsi"]        } on-error={}
    :local total ($wg1 + $wg2)
    :local status "PASS"
    :local detail "msftconnecttest=$wg1, msftncsi=$wg2"
    :if ($total > 0) do={
        :set status "FAIL"
        :set detail ($detail . " -- Windows clients will bypass portal (DEF-010); remove these")
    }
    :put "## $status: walled-garden -- $detail (informational, score unchanged)"
    :set ($summary->[:len $summary]) "$status walled-garden (info)"
    :put ""
}

# === Informational: VRRP HA (no score) =====================================
:if ($runVrrp) do={
    :put "#### Informational: VRRP HA"
    :local vc 0
    :do { :set vc [/interface vrrp print count-only] } on-error={}
    :if ($vc = 0) do={
        :put "## SKIP: vrrp -- no VRRP interfaces"
        :set ($summary->[:len $summary]) "SKIP vrrp (info)"
    } else={
        :local fails 0
        :foreach v in=[/interface vrrp find] do={
            :local r true
            :local inv false
            :do { :set r   [/interface vrrp get $v running] } on-error={}
            :do { :set inv [/interface vrrp get $v invalid] } on-error={}
            :if (!$r or $inv) do={ :set fails ($fails + 1) }
        }
        :local status "PASS"
        :local detail "vrrp interfaces=$vc, in failure state=$fails"
        :if ($fails > 0) do={ :set status "FAIL" }
        :put "## $status: vrrp -- $detail (informational, score unchanged)"
        :set ($summary->[:len $summary]) "$status vrrp (info)"
    }
    :put ""
}

# === Final summary =========================================================
:local rating "?"
:if ($score >= 90) do={ :set rating "HEALTHY" }
:if ($score >= 75 and $score < 90) do={ :set rating "WARNINGS" }
:if ($score >= 50 and $score < 75) do={ :set rating "DEGRADED" }
:if ($score < 50) do={ :set rating "CRITICAL" }

:put "###############################################################"
:put "# Health score: $score / 100   ($rating)"
:put "###############################################################"
:foreach line in=$summary do={ :put "  $line" }
:put ""
:put "Reference: mikrotik-diagnostics.md (thresholds, DEF-### tags, remediation)."
