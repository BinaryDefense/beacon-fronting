# beacon-fronting
A simple command line program to help defender test their detections for network beacon patterns and domain fronting

# Command-line arguments
```
Usage of beacon-fronting.exe:
  -backdomain string
        the origin or backend domain (your real server hostname) (default "vs-update-server.azureedge.net")
  -blanksni
        include -blanksni to use a blank string as the TLS SNI field
  -frontdomain string
        the domain you want to front (default "natick.research.microsoft.com")
  -frontsni
        include -frontsni to use the fronted domain as the TLS SNI field
  -jitter int
        percent (0-99) of variation to randomize poll interval (default 10)
  -poll int
        number of seconds between beacons (default 42)
  -request string
        the request including any query string you want to send (default "/?poll=true")
  -showresponse
        include -showresponse if you want the HTTP response from the server to be printed in the output
  -usefronting
        include -usefronting if you want to use domain fronting, omit if not
  -usehttps
        include -usehttps if you want to use TLS/HTTPS, or omit for unencrypted HTTP
```
# Example usage:
## Simple 60 second polling, no jitter, no domain fronting, use https
./BeaconFrontTest -backdomain httpstat.us -request /200 -usehttps -poll 60 -jitter 0

## 30 second polling with 50% jitter, using domain fronting through azureedge CDN
./BeaconFrontTest -backdomain your-cdn-hostname.azureedge.net -frontdomain natick.research.microsoft.com -usefronting -usehttps -poll 30 -jitter 50 -request /test-page.html?using-query-string=for-no-caching

# Detection Queries
## KQL Query to Detect TLS Domain Fronting for Suricata and Sysmon Events
```
// TLS Domain Fronting Query
Suricata
| where event_type == "dns" and type == "answer" // Look for DNS answers
| mv-expand answers // Split multiple answers into individual rows
| where answers.rrtype in ("A", "AAAA") // Take just the domain to IPv4 or IPv6 answers
| extend rrtype = tostring(answers.rrtype), rdata = tostring(answers.rdata)
| project TimeGenerated, rrname, rrtype, rdata // Output simple passive DNS records: (date,query,type,answer)
// Now take the passive DNS output and join it to TLS connection events
| join kind=inner (Suricata | where event_type=="tls" | project TLSTimeGenerated=TimeGenerated, dst_ip, tls_sni) on $left.rdata == $right.dst_ip
| where rrname != tls_sni // Only examine the records where DNS name is different from SNI name
| where abs(datetime_diff("second", TimeGenerated, TLSTimeGenerated)) < 10 // Only look at DNS and TLS close to the same time
// Optional - remove any results where the DNS name queried was the CNAME answer for the TLS SNI field
//| join kind=leftanti CNAMEs on $left.tls_sni == $right.rrname and $left.rrname == $right.rdata
// Join the Suricata network event data with Sysmon process data to link processes with network traffic
| join kind=inner (Sysmon | where EventID==3 | project ProcessPath, DestinationIp, DestinationPort) on $left.dst_ip == $right.DestinationIp
//| where ProcessPath !endswith @"AppData\Local\Microsoft\Teams\current\Teams.exe"
| summarize make_set(tls_sni, 50), make_set(dst_ip, 50), make_set(ProcessPath, 50) by rrname
```

### CNAMEs Custom Function
```
// CNAMEs custom function (save as function in Sentinel)
Suricata
| where event_type == "dns" and type == "answer" // Look for DNS answers
| mv-expand answers // Split multiple answers into individual rows
| where answers.rrtype == "CNAME" // Take just the CNAME answers
| extend rrtype = tostring(answers.rrtype), rdata = tostring(answers.rdata)
| distinct rrname, rrtype, rdata // Output simple passive DNS records: (query,type,answer)
```

## KQL Query to Detect HTTP (Non-Encrypted) Domain Fronting for Suricata (or if you inspect TLS traffic)
```
// Unencrypted HTTP Domain Fronting Query
Suricata
| where event_type == "dns" and type == "answer"
| mv-expand answers
| where answers.rrtype in ("A", "AAAA")
| extend rrtype = tostring(answers.rrtype), rdata = tostring(answers.rdata)
| project TimeGenerated, rrname, rrtype, rdata
| join kind=inner (Suricata | where event_type=="http" | project HTTPTimeGenerated=TimeGenerated, dst_ip, http_hostname) on $left.rdata == $right.dst_ip
| where rrname != http_hostname
| where abs(datetime_diff("second", TimeGenerated, HTTPTimeGenerated)) < 60
| join kind=inner (Sysmon | where EventID==3 | project ProcessPath, DestinationIp, DestinationPort) on $left.dst_ip == $right.DestinationIp
| summarize make_set(http_hostname,50), make_set(dst_ip,50), make_set(ProcessPath,50) by rrname
```
