package runner

import (
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

func (c *Config) loadFingerprints() error {
	fingerprints, err := Fingerprints()
	if err != nil {
		return err
	}
	c.fingerprints = fingerprints
	return nil
}
