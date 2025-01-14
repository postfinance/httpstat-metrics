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
	"strconv"
	"strings"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"golang.org/x/exp/slog"
)

const (
	lookupTotalName              = "httpstat_lookup_total"
	errorsTotalName              = "httpstat_errors_total"
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
	ctx              context.Context
	httpServerConfig *HTTPServerConfig
	labels           string
	url              url.URL
	trsp             *http.Transport
	lgr              *slog.Logger
	mS               *metrics.Set
}

func newQuerier(ctx context.Context, config HTTPServerConfig, lgr *slog.Logger, insecure bool, tlsCerts []tls.Certificate) (*Querier, error) {
	var q = Querier{
		ctx:              ctx,
		httpServerConfig: &config,
		url:              *parseURL(config.URL),
		lgr:              lgr,
	}

	q.lgr = q.lgr.With(
		"url", config.URL,
		"scheme", q.url.Scheme,
		"ip_version", q.httpServerConfig.IPVersion,
	)

	if len(config.Host) > 0 {
		q.lgr = q.lgr.With(
			"host", config.Host,
		)
	}

	q.trsp = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if q.url.Scheme == "https" {
		var host string

		var err error

		if len(config.Host) > 0 {
			host = config.Host
		} else {
			host, _, err = net.SplitHostPort(q.url.Host)
		}

		if err != nil {
			host = q.url.Host
		}

		q.trsp.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure, //nolint:gosec // not a security concern as we are not actually sending/reading data
			Certificates:       tlsCerts,
			RootCAs:            caCertPool,
			MinVersion:         tls.VersionTLS12,
		}
	}

	var network string

	switch q.httpServerConfig.IPVersion {
	case "4":
		network = "tcp4"
	case "6":
		network = "tcp6"
	case "any":
		network = "tcp"
	default:
		return nil, fmt.Errorf("ip version not configured properly. must be either 4, 6, any")
	}

	q.trsp.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   dialerTimeout,
			DualStack: false,
		}).DialContext(ctx, network, addr)
	}

	labelsMap := q.httpServerConfig.ExtraLabels

	if len(q.httpServerConfig.Host) > 0 {
		labelsMap["host"] = q.httpServerConfig.Host
	}

	labelsMap["url"] = q.httpServerConfig.URL
	labelsMap["scheme"] = q.url.Scheme
	labelsMap["ip_version"] = q.httpServerConfig.IPVersion

	for label, value := range labelsMap {
		q.labels += fmt.Sprintf("%s=%q,", label, value)
	}

	if len(additionalLabels) > 0 {
		q.labels += fmt.Sprintf("%s,", additionalLabels)
	}

	q.labels = q.labels[0 : len(q.labels)-1]

	q.mS = metrics.NewSet()

	q.mS.GetOrCreateCounter(fmt.Sprintf("%s{%s}", lookupTotalName, q.labels)).Set(0)
	q.mS.GetOrCreateCounter(fmt.Sprintf("%s{%s}", errorsTotalName, q.labels)).Set(0)

	metrics.RegisterSet(q.mS)

	return &q, nil
}

// Run starts the querier at the specified interval, with a random jitter of 0-interval
func (q *Querier) Run(interval *time.Duration) {
	//nolint:gosec // No need for a cryptographic secure random number since this is only used for a jitter.
	jitter := time.Duration(rand.Float64() * float64(*interval))

	q.lgr.Info("start a new querier with some delay",
		"jitter", jitter,
	)

	time.Sleep(jitter)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ticker.C:
			q.visit()
		case <-q.ctx.Done():
			break loop
		}
	}

	q.mS.UnregisterAllMetrics()
}

// visit visits a url and times the interaction.
// If the response is a 30x, visit follows the redirect.
//
//nolint:funlen // the httpTrace declaration takes a lot of lines, that cannot be moved away from this function
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

	l := q.labels
	client := &http.Client{
		Transport: q.trsp,
	}
	req = req.WithContext(httptrace.WithClientTrace(q.ctx, trace))
	resp, err := client.Do(req)

	defer q.trsp.CloseIdleConnections()

	if q.ctx.Err() != nil { // the context was most likely canceled, no need to take the measurements into account
		return
	}

	if err != nil {
		q.mS.GetOrCreateCounter(fmt.Sprintf("%s{%s}", lookupTotalName, l)).Inc()
		q.mS.GetOrCreateCounter(fmt.Sprintf("%s{%s}", errorsTotalName, l)).Inc()
		q.lgr.Info("error during query", "error", err)

		return
	}

	l += fmt.Sprintf(",%s=%q", "status_code", strconv.Itoa(resp.StatusCode))
	q.mS.GetOrCreateCounter(fmt.Sprintf("%s{%s}", lookupTotalName, l)).Inc()

	bodySize, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	postBodyReadTime := time.Now()
	l += fmt.Sprintf("%s=%q", ",body_size", strconv.FormatInt(bodySize, 10))

	dnsLookupDuration := dnsDoneTime.Sub(dnsStartTime)
	tcpConnectDuration := connectDoneTime.Sub(connectStartTime)
	tlsHandshakeDuration := tlsHandshakeStopTime.Sub(tlsHandshakeStartTime)
	serverProcessingDuration := gotFirstResponseByteTime.Sub(lastGotConnTime)
	contentTransferDuration := postBodyReadTime.Sub(gotFirstResponseByteTime)
	totalDuration := postBodyReadTime.Sub(getConnTime)

	if !dnsStartTime.IsZero() { // we only record this metric if a DNS lookup was actually made
		q.mS.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", dnsLookupDurationName, l)).Update(dnsLookupDuration.Seconds())
	}

	q.mS.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", tcpConnDurationName, l)).Update(tcpConnectDuration.Seconds())

	if !tlsHandshakeStartTime.IsZero() { // we only record this q.mS when a TLS handshake was done
		q.mS.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", tlsHandshakeDurationName, l)).Update(tlsHandshakeDuration.Seconds())
	}

	q.mS.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", serverProcessingDurationName, l)).Update(serverProcessingDuration.Seconds())
	q.mS.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", contentTransferDurationName, l)).Update(contentTransferDuration.Seconds())
	q.mS.GetOrCreateHistogram(fmt.Sprintf("%s{%s}", totalDurationDurationName, l)).Update(totalDuration.Seconds())

	q.lgr.Debug("new measurement",
		dnsLookupDurationName, dnsLookupDuration,
		tcpConnDurationName, tcpConnectDuration,
		tlsHandshakeDurationName, tlsHandshakeDuration,
		serverProcessingDurationName, serverProcessingDuration,
		contentTransferDurationName, contentTransferDuration,
		totalDurationDurationName, totalDuration,
	)
}

func parseURL(uri string) *url.URL {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	parsedURL, err := url.Parse(uri)

	if err != nil {
		log.Fatalf("could not parse url %q: %v", uri, err)
	}

	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "http"
		if !strings.HasSuffix(parsedURL.Host, ":80") {
			parsedURL.Scheme += "s"
		}
	}

	return parsedURL
}
