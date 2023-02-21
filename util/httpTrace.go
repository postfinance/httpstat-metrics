// main httpTrace.go permits to test the behavior of httpTrace, to make sure we
// interpret measurements correctly
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"
)

func main() {
	req, _ := http.NewRequest(http.MethodGet, "https://www.postfinance.ch/", http.NoBody)
	clientTrace := &httptrace.ClientTrace{
		GetConn:  func(hostPort string) { fmt.Printf("%v\tstarting to create conn\n", time.Now()) },
		DNSStart: func(info httptrace.DNSStartInfo) { fmt.Printf("%v\tstarting to look up dns\n", time.Now()) },
		DNSDone:  func(info httptrace.DNSDoneInfo) { fmt.Printf("%v\tdone looking up dns\n", time.Now()) },
		ConnectStart: func(network, addr string) {
			fmt.Printf("%v\tstarting tcp connection %v %v\n", time.Now(), network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Printf("%v\ttcp connection created %v %v\n", time.Now(), network, addr)
		},
		TLSHandshakeStart:    func() { fmt.Printf("%v\tTLS handshake start\n", time.Now()) },
		TLSHandshakeDone:     func(state tls.ConnectionState, _ error) { fmt.Printf("%v\tTLS handshake done\n", time.Now()) },
		GotConn:              func(info httptrace.GotConnInfo) { fmt.Printf("%v\tconnection established\n", time.Now()) },
		GotFirstResponseByte: func() { fmt.Printf("%v\tfirst response byte received\n", time.Now().String()) },
	}

	clientTraceCtx := httptrace.WithClientTrace(req.Context(), clientTrace)
	req = req.WithContext(clientTraceCtx)
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}
	resp, err := client.Do(req)

	if err != nil {
		return
	}

	bodySize, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Println("body read. size: ", bodySize)
}
