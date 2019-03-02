# MikrotikScripts

To use, enter the command into RouterOS terminal.

## 1. DNS server performance test

CheckDNS will find the DNS servers as configured in IP->DNS and test the performance of each one. After that it will run the same tests as if the mikrotik was acting as a local DNS server before providing results.

<code>/tool fetch url="https://raw.githubusercontent.com/MARKJ78/MikrotikScripts/master/checkDNS.rsc" mode=https;/import checkDNS.rsc</code>