package runner

import (
	"crypto/tls"
	"net/http"
	"time"
)

type Config struct {
	HTTPS        bool
	VerifySSL    bool
	Emoji        bool
	HideFails    bool
	OnlyVuln     bool
	Concurrency  int
	Timeout      int
	Targets      string
	Target       string
	Output       string
	fingerprints []Fingerprint
}

func (s *Config) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !s.VerifySSL},
	}

	timeout := time.Duration(s.Timeout) * time.Second
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	s.client = client
}

func (c *Config) loadFingerprints() error {
	fingerprints, err := Fingerprints()
	if err != nil {
		return err
	}
	c.fingerprints = fingerprints
	return nil
}
