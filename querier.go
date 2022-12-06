package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

const (
	dnsLookupDuration = "httpstat_dns_lookup_duation_seconds"
)

type Querier struct {
	httpServerConfig *HTTPServerConfig
	labels           string
	url              url.URL
	tlsClientConfig  *tls.Config
	tr               *http.Transport
}

func (q *Querier) Run(interval *time.Duration) {

	q.tr = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	switch q.url.Scheme {
	case "https":
		host, _, err := net.SplitHostPort(q.url.Host)
		if err != nil {
			host = q.url.Host
		}

		q.tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
			Certificates:       readClientCert(clientCertFile),
			MinVersion:         tls.VersionTLS12,
		}
	}

	labelsMap := q.httpServerConfig.ExtraLabels
	labelsMap["host"] = q.url.Host
	labelsMap["scheme"] = q.url.Scheme
	labelsMap["ip_version"] = q.httpServerConfig.IpVersion

	q.labels = "{"
	for label, value := range q.httpServerConfig.ExtraLabels {
		q.labels += fmt.Sprintf("%s=%q,", label, value)

	}
	q.labels = q.labels[:len(q.labels)-1] // remove trailing comma
	q.labels += "}"

	metrics.GetOrCreateCounter(fmt.Sprintf("%s%s", dnsLookupDuration, q.labels)).Set(0)

	//nolint:gosec // No need for a cryptographic secure random number since this is only used for a jitter.
	jitter := time.Duration(rand.Float64() * float64(500*time.Millisecond))

	// q.l.Infow("start delayed",
	// 	"jitter", jitter,
	// )

	time.Sleep(jitter)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for range ticker.C {
		q.visit()
	}
}

// visit visits a url and times the interaction.
// If the response is a 30x, visit follows the redirect.
func (q *Querier) visit() {
	req, err := http.NewRequest("GET", q.url.String(), nil)
	if err != nil {
		log.Fatalf("unable to create request: %v", err)
	}
	req.Header = q.httpServerConfig.HttpHeaders
	if q.httpServerConfig.Host != "" {
		req.Host = q.httpServerConfig.Host
	}

	var getConnTime, dnsStartTime, dnsDoneTime, connectStartTime, connectDoneTime, gotConnTime, gotFirstResponseByteTime, tlsHandshakeStartTime, tlsHandshakeStopTime time.Time

	trace := &httptrace.ClientTrace{
		GetConn:  func(hostPort string) { getConnTime = time.Now() },
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStartTime = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDoneTime = time.Now() },
		ConnectStart: func(_, _ string) {
			if connectStartTime.IsZero() {
				// connecting to IP
				connectStartTime = time.Now()
			}
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				log.Fatalf("unable to connect to host %v: %v", addr, err)
			}
			connectDoneTime = time.Now()

		},
		GotConn:              func(_ httptrace.GotConnInfo) { gotConnTime = time.Now() },
		GotFirstResponseByte: func() { gotFirstResponseByteTime = time.Now() },
		TLSHandshakeStart:    func() { tlsHandshakeStartTime = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { tlsHandshakeStopTime = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	switch {
	case fourOnly:
		q.tr.DialContext = dialContext("tcp4")
	case sixOnly:
		q.tr.DialContext = dialContext("tcp6")
	default:
		q.tr.DialContext = dialContext("tcp")
	}

	switch q.url.Scheme {
	case "https":
		q.tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: insecure,
			Certificates:       readClientCert(clientCertFile),
			MinVersion:         tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: q.tr,
	}

	defer q.tr.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		// log.Fatalf("failed to read response: %v", err)
		return
	}

	bodySize, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	postBodyReadTime := time.Now() // after read body
	if dnsStartTime.IsZero() {
		// we skipped DNS
		dnsStartTime = dnsDoneTime
	}

	dnsLookup := dnsDoneTime.Sub(dnsStartTime)
	tcpConnection := connectDoneTime.Sub(connectStartTime)
	tlsHandshake := tlsHandshakeStopTime.Sub(tlsHandshakeStartTime)
	serverProcessing := gotFirstResponseByteTime.Sub(gotConnTime)
	contentTransfer := postBodyReadTime.Sub(gotFirstResponseByteTime)
	totalDuration := postBodyReadTime.Sub(getConnTime)

	fmt.Println(bodySize, dnsLookup, tcpConnection, tlsHandshake, serverProcessing, contentTransfer, totalDuration)
	// httpstat_error_total{code="404"}
	// httpstat_lookup_total{code="404"}

}
