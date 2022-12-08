// main package of the httpstat-metrics package
package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/exp/slog"

	"gopkg.in/yaml.v3"
)

var (
	// Command line flags.
	configFile      string
	httpMethod      string
	postBody        string
	followRedirects bool
	onlyHeader      bool
	insecure        bool
	saveOutput      bool
	outputFile      string
	showVersion     bool
	clientCertFile  string
	fourOnly        bool
	sixOnly         bool
	interval        time.Duration

	// number of redirects followed
	redirectsFollowed int

	version = "devel" // for -v flag, updated during the release process with -ldflags=-X=main.version=...
)

const maxRedirects = 10

func init() {
	flag.StringVar(&configFile, "config", "config.yaml", "path to the configuration file")
	flag.BoolVar(&insecure, "k", false, "allow insecure SSL connections")
	flag.BoolVar(&saveOutput, "O", false, "save body as remote filename")
	flag.StringVar(&outputFile, "o", "", "output file for body")
	flag.BoolVar(&showVersion, "v", false, "print version number")
	flag.StringVar(&clientCertFile, "E", "", "client cert file for tls config")
	flag.BoolVar(&fourOnly, "4", false, "resolve IPv4 addresses only")
	flag.BoolVar(&sixOnly, "6", false, "resolve IPv6 addresses only")
	flag.DurationVar(&interval, "interval", 1*time.Second, "interval between http queries. must be in Go time.ParseDuration format, e.g. 5s or 5m or 1h, etc")

	flag.Usage = usage
}

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

type HTTPServerConfig struct {
	URL         string            `yaml:"url"`
	IPVersion   string            `yaml:"ipVersion"`
	Host        string            `yaml:"host"`
	HTTPHeaders http.Header       `yaml:"headers"`
	ExtraLabels map[string]string `yaml:"extraLabels"` // TODO: check VM instrumentation if there is a label
}

type Config struct {
	HTTPServers []HTTPServerConfig `yaml:"endpoints"`
	Test        string             `yaml:"test"`
}

func (c *Config) readConf() {

	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("couldn't open the config file %s, error message: #%v ", configFile, err)
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		slog.Log(slog.ErrorLevel, "Unmarshal error", err)
	}
}

func main() {
	flag.Parse()

	lgr := slog.New(slog.NewTextHandler(os.Stdout))
	lgr = lgr.With("app", "httpstat-metrics", "version", version)
	slog.SetDefault(lgr)

	var config Config

	config.readConf()

	lgr.Info("starting up", "runtime-version", runtime.Version())

	if fourOnly && sixOnly {
		fmt.Fprintf(os.Stderr, "%s: Only one of -4 and -6 may be specified\n", os.Args[0])
		os.Exit(-1)
	}

	for idx, httpConfig := range config.HTTPServers {
		var querier = Querier{
			httpServerConfig: &config.HTTPServers[idx],
			url:              *parseURL(httpConfig.URL),
		}

		querier.Run(&interval)
	}
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
	certFileBytes, err := ioutil.ReadFile(filename)
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
		log.Fatalf("unable to load client cert and key pair: %v", err)
	}
	return []tls.Certificate{cert}
}

func parseURL(uri string) *url.URL {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		log.Fatalf("could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url
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
