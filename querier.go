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
	"golang.org/x/exp/slog"
)

const (
	dnsLookupDuration = "httpstat_dns_lookup_duation_seconds"
	lookupTotalName   = "httpstat_lookup_total"
	errorTotalName    = "httpstat_error_total"
)

// Querier A querier will periodically measure the host specified in its
// config, and will export the observations as prometheus metrics
type Querier struct {
	httpServerConfig *HTTPServerConfig
	labels           string
	url              url.URL
	tr               *http.Transport
	lgr              *slog.Logger
}

func (q *Querier) init() {
	q.tr = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if q.url.Scheme == "https" {
		host, _, err := net.SplitHostPort(q.url.Host)
		if err != nil {
			host = q.url.Host
		}

		q.tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure, //nolint:gosec // not a security concern as we are not actually sending/reading data
			Certificates:       readClientCert(clientCertFile),
			MinVersion:         tls.VersionTLS12,
		}
	}

	switch q.httpServerConfig.IPVersion {
	case "4":
		q.tr.DialContext = dialContext("tcp4")
	case "6":
		q.tr.DialContext = dialContext("tcp6")
	case "any":
		q.tr.DialContext = dialContext("tcp")
	default:
		log.Fatal("")
	}

	q.lgr = q.lgr.With(
		"host", q.url.Host,
		"scheme", q.url.Scheme,
		"ip_version", q.httpServerConfig.IPVersion,
	)

	labelsMap := q.httpServerConfig.ExtraLabels
	labelsMap["host"] = q.url.Host
	labelsMap["scheme"] = q.url.Scheme
	labelsMap["ip_version"] = q.httpServerConfig.IPVersion

	for label, value := range q.httpServerConfig.ExtraLabels {
		q.labels += fmt.Sprintf("%s=%q,", label, value)
	}

	q.labels = q.labels[0 : len(q.labels)-1]

	metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", lookupTotalName, q.labels)).Set(0)
	metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", errorTotalName, q.labels)).Set(0)
}

// Run starts the querier at the specified interval, with a random jitter of 0-500ms
func (q *Querier) Run(interval *time.Duration) {
	q.init()

	//nolint:gosec // No need for a cryptographic secure random number since this is only used for a jitter.
	jitter := time.Duration(rand.Float64() * float64(500*time.Millisecond))

	q.lgr.Info("start delayed",
		"jitter", jitter,
	)

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
	req, _ := http.NewRequest("GET", q.url.String(), http.NoBody) // we ignore the err as the URL has already been parsed and is therefore valid

	req.Header = q.httpServerConfig.HTTPHeaders
	if q.httpServerConfig.Host != "" {
		req.Host = q.httpServerConfig.Host
	}

	var getConnTime, dnsStartTime, dnsDoneTime, connectStartTime, connectDoneTime,
		gotConnTime, gotFirstResponseByteTime, tlsHandshakeStartTime,
		tlsHandshakeStopTime time.Time

	trace := &httptrace.ClientTrace{
		GetConn:  func(hostPort string) { getConnTime = time.Now() },
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStartTime = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDoneTime = time.Now() },
		ConnectStart: func(_, _ string) {
			if connectStartTime.IsZero() {
				connectStartTime = time.Now()
			}
		},
		ConnectDone: func(net, addr string, err error) {
			connectDoneTime = time.Now()
		},
		GotConn:              func(_ httptrace.GotConnInfo) { gotConnTime = time.Now() },
		GotFirstResponseByte: func() { gotFirstResponseByteTime = time.Now() },
		TLSHandshakeStart:    func() { tlsHandshakeStartTime = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { tlsHandshakeStopTime = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	client := &http.Client{
		Transport: q.tr,
	}

	defer q.tr.CloseIdleConnections()

	resp, err := client.Do(req)
	l := q.labels

	if err != nil {
		metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", lookupTotalName, l)).Inc()
		metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", errorTotalName, l)).Inc()

		return
	}

	l += fmt.Sprintf("%s=%q", "status_code", resp.StatusCode)
	metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", lookupTotalName, l)).Inc()

	defer resp.Body.Close()
	bodySize, _ := io.Copy(io.Discard, resp.Body)
	postBodyReadTime := time.Now() // after read body

	dnsLookup := dnsDoneTime.Sub(dnsStartTime)
	tcpConnection := connectDoneTime.Sub(connectStartTime)
	tlsHandshake := tlsHandshakeStopTime.Sub(tlsHandshakeStartTime)
	serverProcessing := gotFirstResponseByteTime.Sub(gotConnTime)
	contentTransfer := postBodyReadTime.Sub(gotFirstResponseByteTime)
	totalDuration := postBodyReadTime.Sub(getConnTime)

	fmt.Println(bodySize, dnsLookup, tcpConnection, tlsHandshake, serverProcessing, contentTransfer, totalDuration)
}
