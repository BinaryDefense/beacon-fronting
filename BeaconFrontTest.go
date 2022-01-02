package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"

	//"net/http/httputil"
	"flag"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		os.Exit(0)
	}()
}

func main() {
	// Set up command line argument options, default values, and help text
	frontedDomainPtr := flag.String("frontdomain", "natick.research.microsoft.com", "the domain you want to front")
	backendDomainPtr := flag.String("backdomain", "vs-update-server.azureedge.net", "the origin or backend domain (your real server hostname)")
	pollingPtr := flag.Int("poll", 42, "number of seconds between beacons")
	jitterPtr := flag.Int("jitter", 10, "percent (0-99) of variation to randomize poll interval")
	frontPtr := flag.Bool("usefronting", false, "include -usefronting if you want to use domain fronting, omit if not")
	useHTTPSPtr := flag.Bool("usehttps", false, "include -usehttps if you want to use TLS/HTTPS, or omit for unencrypted HTTP")
	requestPtr := flag.String("request", "/?poll=true", "the request including any query string you want to send")
	showresponsePtr := flag.Bool("showresponse", false, "include -showresponse if you want the HTTP response from the server to be printed in the output")
	flag.Parse() // get the command line args
	SetupCloseHandler()

	var proto string
	var client *http.Client
	var req *http.Request
	var res *http.Response
	var err error

	if *jitterPtr > 99 || *jitterPtr < 0 {
		*jitterPtr = 10
	}

	proto = "http://"
	if *useHTTPSPtr {
		proto = "https://"
	}

	if *frontPtr {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					ServerName: *backendDomainPtr, // Set the backend domain as the SNI value
				},
			},
		}
		url := proto + *frontedDomainPtr + *requestPtr
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(err)
		}
		// Set the HTTP host header to the backend domain
		req.Host = *backendDomainPtr
	} else {
		client = &http.Client{}
		url := proto + *backendDomainPtr + *requestPtr
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	rand.Seed(time.Now().UnixNano())

	for { // ctrl-c to exit this loop
		now := time.Now()
		fmt.Printf("%s: Beacon sent to %s with HTTP Host: %s\n", now, req.URL, req.Host)
		res, err = client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer res.Body.Close()

		if *showresponsePtr {
			io.Copy(os.Stdout, res.Body)
		}

		// Add Jitter to polling interval and sleep that long
		thisJitter := 0
		if *jitterPtr > 0 {
			thisJitter = rand.Intn(int(math.Ceil((float64)(*pollingPtr) * ((float64)(*jitterPtr) / 100.0))))
		}
		thisSleepTime := time.Duration((*pollingPtr + thisJitter)) * time.Second
		now = time.Now()
		fmt.Printf("%s: Sleeping for %d seconds\n", now, (thisSleepTime / time.Second))
		time.Sleep(thisSleepTime)
	}

}
