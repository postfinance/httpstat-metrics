package main

import (
	"testing"

	"github.com/mitchellh/hashstructure/v2"
)

func TestParseURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://golang.org", "https://golang.org"},
		{"https://golang.org:443/test", "https://golang.org:443/test"},
		{"localhost:8080/test", "https://localhost:8080/test"},
		{"localhost:80/test", "http://localhost:80/test"},
		{"//localhost:8080/test", "https://localhost:8080/test"},
		{"//localhost:80/test", "http://localhost:80/test"},
	}

	for _, test := range tests {
		u := parseURL(test.in)
		if u.String() != test.want {
			t.Errorf("Given: %s\nwant: %s\ngot: %s", test.in, test.want, u.String())
		}
	}
}

func TestHashConfig(t *testing.T) {

	c1 := HTTPServerConfig{
		Host:      "abcd.ch",
		URL:       "server101.comp.ch",
		IPVersion: "any",
		ExtraLabels: map[string]string{
			"Allow-Compression": "true",
			"Some-Header":       "Some-Value",
		},
	}

	c2 := HTTPServerConfig{
		Host:      "abcd.ch",
		URL:       "server101.comp.ch",
		IPVersion: "any",
		ExtraLabels: map[string]string{
			"Allow-Compression": "true",
		},
	}

	h1, _ := hashstructure.Hash(c1, hashstructure.FormatV2, nil)
	h2, _ := hashstructure.Hash(c2, hashstructure.FormatV2, nil)

	if h1 == h2 {
		t.Error("comparison of HTTP Config with hashv2 should not have been identical")
	}

	c2.ExtraLabels["Some-Header"] = "Some-Value"
	h2, _ = hashstructure.Hash(c2, hashstructure.FormatV2, nil)

	if h1 == h2 {
		t.Error("comparison of HTTP Config with hashv2 should not have been identical")
	}
}
