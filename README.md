# beacon-fronting
A simple command line program to help defender test their detections for network beacon patterns and domain fronting

# Command-line arguments
Usage of ./BeaconFrontTest:
  -backdomain string
        the origin or backend domain (your real server hostname) (default "vs-update-server.azureedge.net")
  -frontdomain string
        the domain you want to front (default "natick.research.microsoft.com")
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

# Example usage:
## Simple 60 second polling, no jitter, no domain fronting, use https
./BeaconFrontTest -backdomain httpstat.us -request /200 -usehttps -poll 60 -jitter 0

## 30 second polling with 50% jitter, using domain fronting through azureedge CDN
./BeaconFrontTest -backdomain your-cdn-hostname.azureedge.net -frontdomain natick.research.microsoft.com -usefronting -usehttps -poll 30 -jitter 50 -request /test-page.html?using-query-string=for-no-caching


