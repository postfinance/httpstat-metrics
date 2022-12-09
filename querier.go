package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"golang.org/x/exp/slog"
)

const (
	lookupTotalName              = "httpstat_lookup_total"
	errorTotalName               = "httpstat_error_total"
	dnsLookupDurationName        = "httpstat_dns_lookup_duration_seconds"
	tcpConnDurationName          = "httpstat_tcp_connection_duration_seconds"
	tlsHandshakeDurationName     = "httpstat_tls_handshake_duration_seconds"
	serverProcessingDurationName = "httpstat_server_processing_duration_seconds"
	contentTransferDurationName  = "httpstat_content_transfer_duration_seconds"
	totalDurationDurationName    = "httpstat_total_duration_seconds"
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

func (q *Querier) init() error {
	q.lgr = q.lgr.With(
		"host", q.url.Host,
		"scheme", q.url.Scheme,
		"ip_version", q.httpServerConfig.IPVersion,
	)

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
		return fmt.Errorf("ip version not configured properly. must be either 4, 6, any")
	}

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

	return nil
}

// Run starts the querier at the specified interval, with a random jitter of 0-500ms
func (q *Querier) Run(interval *time.Duration) {
	err := q.init()

	if err != nil {
		q.lgr.Error("querier initialization failed", err)
		return
	}

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
		gotConnTime, lastGotConnTime, gotFirstResponseByteTime, tlsHandshakeStartTime,
		tlsHandshakeStopTime time.Time

	trace := &httptrace.ClientTrace{
		GetConn: func(_ string) {
			if getConnTime.IsZero() {
				getConnTime = time.Now()
			}
		},
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStartTime = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDoneTime = time.Now() },
		ConnectStart: func(_, _ string) {
			if connectStartTime.IsZero() {
				connectStartTime = time.Now()
			}
		},
		ConnectDone: func(_, _ string, _ error) {
			if connectDoneTime.IsZero() {
				connectDoneTime = time.Now()
			}
			lastGotConnTime = time.Now()
		},
		TLSHandshakeStart: func() { tlsHandshakeStartTime = time.Now() },
		TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { tlsHandshakeStopTime = time.Now() },
		GotConn: func(_ httptrace.GotConnInfo) {
			if gotConnTime.IsZero() {
				gotConnTime = time.Now()
			}
			lastGotConnTime = time.Now()
		},
		GotFirstResponseByte: func() {
			// we only care about the last time it happens (in case there were redirects for example)
			gotFirstResponseByteTime = time.Now()
		},
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

	l += fmt.Sprintf(",%s=%q", "status_code", strconv.Itoa(resp.StatusCode))
	metrics.GetOrCreateCounter(fmt.Sprintf("%s{%s}", lookupTotalName, l)).Inc()

	defer resp.Body.Close()
	bodySize, _ := io.Copy(io.Discard, resp.Body)
	postBodyReadTime := time.Now()
	l += fmt.Sprintf("%s=%q", ",body_size", strconv.FormatInt(bodySize, 10))

	dnsLookupDuration := dnsDoneTime.Sub(dnsStartTime)
	tcpConnectDuration := connectDoneTime.Sub(connectStartTime)
	tlsHandshakeDuration := tlsHandshakeStopTime.Sub(tlsHandshakeStartTime)
	serverProcessingDuration := gotFirstResponseByteTime.Sub(lastGotConnTime)
	contentTransferDuration := postBodyReadTime.Sub(gotFirstResponseByteTime)
	totalDuration := postBodyReadTime.Sub(getConnTime)

	if !dnsStartTime.IsZero() { // we only record this metric if a DNS lookup was actually made
		metrics.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", dnsLookupDurationName, l)).Update(float64(dnsLookupDuration))
	}

	metrics.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", tcpConnDurationName, l)).Update(float64(tcpConnectDuration))

	if !tlsHandshakeStartTime.IsZero() { // we only record this metrics when a TLS handshake was done
		metrics.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", tlsHandshakeDurationName, l)).Update(float64(tlsHandshakeDuration))
	}

	metrics.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", serverProcessingDurationName, l)).Update(float64(serverProcessingDuration))
	metrics.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", contentTransferDurationName, l)).Update(float64(contentTransferDuration))
	metrics.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", totalDurationDurationName, l)).Update(float64(totalDuration))

	q.lgr.Debug("new measurement",
		dnsLookupDurationName, dnsLookupDuration,
		tcpConnDurationName, tcpConnectDuration,
		tlsHandshakeDurationName, tlsHandshakeDuration,
		serverProcessingDurationName, serverProcessingDuration,
		contentTransferDurationName, contentTransferDuration,
		totalDurationDurationName, totalDuration,
	)
}
