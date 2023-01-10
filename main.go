// main package of the httpstat-metrics package
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/mitchellh/hashstructure/v2"
	"golang.org/x/exp/slog"

	"gopkg.in/yaml.v3"
)

var (
	version    = "devel"      // for -v flag, updated during the release process with -ldflags=-X=main.version=...
	caCertPool *x509.CertPool //nolint:gochecknoglobals // the caCertPool is used throughout the program
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

var errSkipReload = errors.New("skip config reload - already latest config active")

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
	HTTPServers   []HTTPServerConfig `yaml:"endpoints"`
	hashConfigMap map[uint64]HTTPServerConfig
	lastYamlHash  string
}

//nolint:funlen // all variables are declared within main, easier without other functions
func main() {
	configFile := flag.String("config", "config.yaml", "path or URL to a config file, or path to a directory containing config files")
	clientCertFile := flag.String("client-cert-file", "", "client cert file for tls config (contains public and private key)")
	caCertFile := flag.String("ca-cert-file", "", "ca file containing additional PEM CAs")
	insecure := flag.Bool("insecure", false, "allow insecure SSL connections")
	debug := flag.Bool("debug", false, "increase logging verbosity")
	interval := flag.Duration("interval", 5*time.Second, "interval between http queries. must be in Go time.ParseDuration format, e.g. 5s or 5m or 1h, etc")

	flag.Usage = usage

	flag.Parse()

	var logLevel slog.Leveler
	if *debug {
		logLevel = slog.DebugLevel
	} else {
		logLevel = slog.InfoLevel
	}

	lgr := slog.New(slog.HandlerOptions{Level: logLevel}.NewTextHandler(os.Stdout))
	lgr = lgr.With("app", "httpstat-metrics", "version", version)
	slog.SetDefault(lgr)
	lgr.Info("starting up", "runtime-version", runtime.Version())

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

	var srvError error

	var config Config
	config.hashConfigMap = make(map[uint64]HTTPServerConfig)

	tlsCert := readClientCert(*clientCertFile)
	caCertPool = readCACert(*caCertFile)
	querierConfigMap := make(map[uint64]context.CancelFunc)

	go func() {
		srvError = srv.ListenAndServe()
	}()

	for {
		if srvError != nil {
			lgr.Error("http server error, exiting.", srvError)
			os.Exit(1)
		}

		switch err := config.readConf(*configFile); err {
		case nil:
		case errSkipReload:
			goto wait
		default:
			if config.lastYamlHash == "" {
				lgr.Error("Could not read a config file on first start. exiting", err)
				os.Exit(1)
			}

			lgr.Error("couldn't read / parse the config", err)

			goto wait
		}

		// first remove any querier that isn't contained in the config anymore
		for querierConfigHash, cancelFn := range querierConfigMap {
			if _, ok := config.hashConfigMap[querierConfigHash]; !ok {
				cancelFn() // cancel the querier context
				delete(querierConfigMap, querierConfigHash)
			}
		}

		// now create queriers for config hashes not yet in querierConfigMap
		for _, conf := range config.HTTPServers {
			h, _ := hashstructure.Hash(conf, hashstructure.FormatV2, nil)

			if _, ok := querierConfigMap[h]; !ok {
				ctx, cancel := context.WithCancel(context.Background())
				q, err := newQuerier(ctx, conf, lgr, *insecure, tlsCert)

				if err != nil {
					lgr.Error("unable to create new querier", err)
					continue
				}

				querierConfigMap[h] = cancel

				go q.Run(interval)
			}
		}

		// and finally wait for 1 minute before reading the configuration again
	wait:
		time.Sleep(60 * time.Second)
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

// readCACert - helper function to read CA certs
// from pem formatted file
func readCACert(filename string) (pool *x509.CertPool) {
	pool, _ = x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}

	if filename == "" {
		return
	}

	// read client certificate file
	certFileBytes, err := os.ReadFile(filename) //nolint:gosec // we read the CAs from the given filename
	if err != nil {
		log.Fatalf("failed to read CA certificates file: %v", err)
	}

	ok := pool.AppendCertsFromPEM(certFileBytes)
	if !ok {
		slog.Warn("couldn't parse additional ca certs, continuing with system CA only")
	}

	return pool
}

func getConfigFromURL(configSrc string) ([]byte, error) {
	trsp := http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caCertPool,
	}}
	cl := http.Client{
		Transport: &trsp,
	}

	resp, err := cl.Get(configSrc)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	config := new(bytes.Buffer)
	_, err = io.CopyN(config, resp.Body, 512*1024)

	if err != io.EOF {
		slog.Error("couldn't reach EOF for config file source. make sure the file is less than 512 KiB", err)
		return nil, err
	}

	return config.Bytes(), nil
}

func mergeConfig(configs [][]byte) ([]byte, error) {
	mergedCfg := &Config{}

	for _, conf := range configs {
		c := &Config{}
		err := yaml.Unmarshal(conf, c)

		if err != nil {
			slog.Log(slog.ErrorLevel, "Unmarshal error", "error", err)
			continue
		}

		mergedCfg.HTTPServers = append(mergedCfg.HTTPServers, c.HTTPServers...)
	}

	return yaml.Marshal(mergedCfg)
}

func getConfigFromDir(configSrc string) ([]byte, error) {
	files, err := os.ReadDir(configSrc)
	if err != nil {
		log.Fatal(err)
	}

	configs := make([][]byte, 0)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if strings.HasSuffix(file.Name(), ".url") {
			cfgURLbytes, err := os.ReadFile(configSrc + file.Name()) //nolint:gosec // reading url from file
			if err != nil {
				continue
			}

			cfgURL := string(cfgURLbytes)

			if !strings.HasPrefix(cfgURL, "http://") && !strings.HasPrefix(cfgURL, "https://") {
				slog.Log(slog.DebugLevel, ".url config file containing invalid URL. the URL must be prefixed with http{,s}://")
				continue
			}

			cfgURL = strings.TrimSpace(cfgURL)

			config, err := getConfigFromURL(cfgURL)
			if err != nil {
				slog.Log(slog.DebugLevel, "unable to get config from URL", "error", err)
				continue
			}

			configs = append(configs, config)
		} else if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			config, err := os.ReadFile(configSrc + file.Name()) //nolint:gosec // reading config files from disk
			if err != nil {
				slog.Log(slog.DebugLevel, "unable to read config from file", "fileName", file.Name(), "error", err)
			}

			configs = append(configs, config)
		}
	}

	return mergeConfig(configs)
}

func (c *Config) readConf(configSrc string) error {
	var config []byte

	var err error

	if strings.Index(configSrc, "http://") == 0 || strings.Index(configSrc, "https://") == 0 {
		config, err = getConfigFromURL(configSrc)
	} else {
		var cfgFileInfo fs.FileInfo
		cfgFileInfo, err = os.Stat(configSrc)
		if err == nil {
			if cfgFileInfo.IsDir() {
				config, err = getConfigFromDir(configSrc)
			} else {
				config, err = os.ReadFile(configSrc) //nolint:gosec // reading config files from disk
			}
		}
	}

	if err != nil {
		slog.Error("couldn't open the config file", err, "configSource", configSrc)
		return err
	}

	newHashbyte := sha256.Sum256(config)
	newHash := fmt.Sprintf("%x", newHashbyte)

	if newHash == c.lastYamlHash {
		return errSkipReload
	}

	err = yaml.Unmarshal(config, &c)
	if err != nil {
		slog.Log(slog.ErrorLevel, "Unmarshal error", err)
		return err
	}

	for k := range c.hashConfigMap {
		delete(c.hashConfigMap, k)
	}

	for _, conf := range c.HTTPServers {
		h, _ := hashstructure.Hash(conf, hashstructure.FormatV2, nil)
		c.hashConfigMap[h] = conf
	}

	c.lastYamlHash = newHash

	return nil
}
