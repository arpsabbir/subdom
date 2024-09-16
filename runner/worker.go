package runner

import (
	"fmt"
	"net"
	"strings"

	"github.com/logrusorgru/aurora"
)

type resultStatus string

const (
	ResultVulnerable    resultStatus = "vulnerable"
	ResultNotVulnerable resultStatus = "not vulnerable"
	ResultCNAME        resultStatus = "cname"
)

type Result struct {
	ResStatus resultStatus
	Status    aurora.Value
	Entry     Fingerprint
}

type Config struct {
	fingerprints []Fingerprint
	HTTPS        bool
	client       *http.Client // Ensure this is set if needed for any future use
}

func (c *Config) checkSubdomain(subdomain string) Result {
	// Perform the CNAME lookup
	cname, err := net.LookupCNAME(subdomain)
	if err != nil {
		fmt.Printf("Error resolving CNAME for %s: %v\n", subdomain, err)
		return Result{ResStatus: ResultCNAME, Status: aurora.Red("CNAME ERROR"), Entry: Fingerprint{}}
	}

	if cname != "" && cname != subdomain {
		fmt.Printf("CNAME for %s: %s\n", subdomain, cname)
		return c.validateCNAME(cname)
	}

	// If no CNAME, use the original subdomain
	return c.validateCNAME(subdomain)
}

func (c *Config) validateCNAME(cname string) Result {
	// For each fingerprint, check if it matches the CNAME (assuming fingerprints are domain names or patterns)
	for _, fp := range c.fingerprints {
		if strings.Contains(cname, fp.Fingerprint) {
			if confirmsVulnerability(cname, fp) {
				return Result{
					ResStatus: ResultVulnerable,
					Status:    aurora.Green("VULNERABLE"),
					Entry:     fp,
				}
			}
			if hasNonVulnerableIndicators(fp) {
				return Result{
					ResStatus: ResultNotVulnerable,
					Status:    aurora.Red("NOT VULNERABLE"),
					Entry:     fp,
				}
			}
		}
	}
	return Result{
		ResStatus: ResultNotVulnerable,
		Status:    aurora.Red("NOT VULNERABLE"),
		Entry:     Fingerprint{},
	}
}

func hasNonVulnerableIndicators(fp Fingerprint) bool {
	// Add your logic here to determine if the fingerprint has non-vulnerable indicators
	return fp.NXDomain
}

func confirmsVulnerability(cname string, fp Fingerprint) bool {
	if fp.NXDomain {
		return false
	}

	if fp.Fingerprint != "" {
		if strings.Contains(cname, fp.Fingerprint) {
			return true
		}
	}

	return false
}

// isValidUrl is a placeholder function to validate URLs.
// You can remove or modify this function as needed.
func isValidUrl(url string) bool {
	// Add your URL validation logic here if needed
	return true
}
