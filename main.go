// main package of the httpstat-metrics package
package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"golang.org/x/exp/slog"

	"gopkg.in/yaml.v3"
)

//nolint:gochecknoglobals // TODO: stop using globals for those flags
var (
	// Command line flags.
	configFile     string
	clientCertFile string
	insecure       bool
	showVersion    bool
	debug          bool
	interval       time.Duration

	version = "devel" // for -v flag, updated during the release process with -ldflags=-X=main.version=...
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] URL\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "ENVIRONMENT:")
	fmt.Fprintln(os.Stderr, "  HTTP_PROXY    proxy for HTTP requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "                used for HTTPS requests if HTTPS_PROXY undefined")
	fmt.Fprintln(os.Stderr, "  HTTPS_PROXY   proxy for HTTPS requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "  NO_PROXY      comma-separated list of hosts to exclude from proxy")
}

// HTTPServerConfig contains the config for each Host we will query
type HTTPServerConfig struct {
	URL         string            `yaml:"url"`
	IPVersion   string            `yaml:"ipVersion"`
	Host        string            `yaml:"host"`
	HTTPHeaders http.Header       `yaml:"headers"`
	ExtraLabels map[string]string `yaml:"extraLabels"` // TODO: check VM instrumentation if there is a label
}

// Config contains the config of the httpstat-metrics app
type Config struct {
	HTTPServers []HTTPServerConfig `yaml:"endpoints"`
	Test        string             `yaml:"test"`
}

func (c *Config) readConf() {
	yamlFile, err := os.ReadFile(configFile) //nolint:gosec // used to load and unmarshal a text config file
	if err != nil {
		log.Fatalf("couldn't open the config file %s, error message: %v ", configFile, err)
	}

	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		slog.Log(slog.ErrorLevel, "Unmarshal error", err)
	}
}

func main() {
	flag.StringVar(&configFile, "config", "config.yaml", "path to the configuration file")
	flag.StringVar(&clientCertFile, "E", "", "client cert file for tls config")
	flag.BoolVar(&insecure, "k", false, "allow insecure SSL connections")
	flag.BoolVar(&showVersion, "v", false, "print version number")
	flag.BoolVar(&debug, "debug", false, "increase logging verbosity")
	flag.DurationVar(&interval, "interval", 5*time.Second, "interval between http queries. must be in Go time.ParseDuration format, e.g. 5s or 5m or 1h, etc")

	flag.Usage = usage

	flag.Parse()

	var logLevel slog.Leveler
	if debug {
		logLevel = slog.DebugLevel
	} else {
		logLevel = slog.InfoLevel
	}

	lgr := slog.New(slog.HandlerOptions{Level: logLevel}.NewTextHandler(os.Stdout))
	lgr = lgr.With("app", "httpstat-metrics", "version", version)
	slog.SetDefault(lgr)

	var config Config

	config.readConf()

	lgr.Info("starting up", "runtime-version", runtime.Version())

	for idx, httpConfig := range config.HTTPServers {
		var querier = Querier{
			httpServerConfig: &config.HTTPServers[idx],
			url:              *parseURL(httpConfig.URL),
			lgr:              lgr,
		}

		go querier.Run(&interval)
	}

	http.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		metrics.WritePrometheus(w, false)
	})

	srv := &http.Server{
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           http.DefaultServeMux,
		Addr:              ":9090",
	}

	err := srv.ListenAndServe()
	lgr.Info("http server finished serving", "error", err)
}

// readClientCert - helper function to read client certificate
// from pem formatted file
func readClientCert(filename string) []tls.Certificate {
	if filename == "" {
		return nil
	}

	var (
		pkeyPem []byte
		certPem []byte
	)

	// read client certificate file (must include client private key and certificate)
	certFileBytes, err := os.ReadFile(filename) //nolint:gosec // we read the cert from the given filename
	if err != nil {
		log.Fatalf("failed to read client certificate file: %v", err)
	}

	for {
		block, rest := pem.Decode(certFileBytes)
		if block == nil {
			break
		}

		certFileBytes = rest

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			pkeyPem = pem.EncodeToMemory(block)
		}

		if strings.HasSuffix(block.Type, "CERTIFICATE") {
			certPem = pem.EncodeToMemory(block)
		}
	}

	cert, err := tls.X509KeyPair(certPem, pkeyPem)
	if err != nil {
		log.Fatal(err)
	}

	return []tls.Certificate{cert}
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

func dialContext(network string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext(ctx, network, addr)
	}
}
