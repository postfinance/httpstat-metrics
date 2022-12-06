package main

import (
	"fmt"
	"math/rand"
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
}

func (q *Querier) Run(interval *time.Duration) {

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
		visit(&q.url)
	}
}
