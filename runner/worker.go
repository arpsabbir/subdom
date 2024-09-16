package runner

import (
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora"
)

type resultStatus string

const (
	ResultHTTPError     resultStatus = "http error"
	ResultResponseError resultStatus = "response error"
	ResultVulnerable    resultStatus = "vulnerable"
	ResultNotVulnerable resultStatus = "not vulnerable"
	ResultCNAMEError    resultStatus = "cname error"
	ResultDNSCheck     resultStatus = "dns check"
)

type Result struct {
	ResStatus    resultStatus
	Status       aurora.Value
	Entry        Fingerprint
	ResponseBody string
}

func (c *Config) checkSubdomain(subdomain string) Result {
	// Perform the CNAME lookup
	cname, err := net.LookupCNAME(subdomain)
	if err != nil {
		// If CNAME lookup fails, use the original URL
		if c.HTTPS {
			subdomain = "https://" + subdomain
		} else {
			subdomain = "http://" + subdomain
		}
	} else if cname != "" && cname != subdomain {
		// Handle CNAME: Use the CNAME target
		rootDomain := extractRootDomain(cname)
		if rootDomain != "" {
			// Perform DNS and SOA checks
			dnsCheckResult := checkDNSRecordsForCNAME(rootDomain)
			if dnsCheckResult != "" {
				return Result{
					ResStatus:    ResultDNSCheck,
					Status:       aurora.Yellow("DNS CHECK"),
					Entry:        Fingerprint{},
					ResponseBody: dnsCheckResult,
				}
			}
		}
		// Fall back to HTTP check for CNAME
		subdomain = "http://" + cname
	}

	// Perform HTTP request
	resp, err := c.client.Get(subdomain)
	if err != nil {
		return Result{ResStatus: ResultHTTPError, Status: aurora.Red("HTTP ERROR"), Entry: Fingerprint{}, ResponseBody: ""}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{ResStatus: ResultResponseError, Status: aurora.Red("RESPONSE ERROR"), Entry: Fingerprint{}, ResponseBody: ""}
	}

	body := string(bodyBytes)

	return c.matchResponse(body)
}

func (c *Config) matchResponse(body string) Result {
	for _, fp := range c.fingerprints {
		if strings.Contains(body, fp.Fingerprint) {
			if confirmsVulnerability(body, fp) {
				return Result{
					ResStatus:    ResultVulnerable,
					Status:       aurora.Green("VULNERABLE"),
					Entry:        fp,
					ResponseBody: body,
				}
			}
			if hasNonVulnerableIndicators(fp) {
				return Result{
					ResStatus:    ResultNotVulnerable,
					Status:       aurora.Red("NOT VULNERABLE"),
					Entry:        fp,
					ResponseBody: body,
				}
			}
		}
	}
	return Result{
		ResStatus:    ResultNotVulnerable,
		Status:       aurora.Red("NOT VULNERABLE"),
		Entry:        Fingerprint{},
		ResponseBody: body,
	}
}

func hasNonVulnerableIndicators(fp Fingerprint) bool {
	return fp.NXDomain
}

func confirmsVulnerability(body string, fp Fingerprint) bool {
	if fp.NXDomain {
		return false
	}

	if fp.Fingerprint != "" {
		re, err := regexp.Compile(fp.Fingerprint)
		if err != nil {
			log.Printf("Error compiling regex for fingerprint %s: %v", fp.Fingerprint, err)
			return false
		}
		if re.MatchString(body) {
			return true
		}
	}

	return false
}

// extractRootDomain extracts the root domain from a CNAME record.
func extractRootDomain(cname string) string {
	parts := strings.Split(cname, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return ""
}

// checkDNSRecordsForCNAME performs DNS and SOA lookups for the root domain.
func checkDNSRecordsForCNAME(domain string) string {
	soaRecords, err := net.LookupSOA(domain)
	if err != nil {
		return fmt.Sprintf("SOA ERROR: %v", err)
	}

	if len(soaRecords) > 0 {
		soaRecord := soaRecords[0]
		return fmt.Sprintf("SOA Record: %s %s %d %d %d %d %d", soaRecord.MName, soaRecord.RName, soaRecord.Serial, soaRecord.Refresh, soaRecord.Retry, soaRecord.Expire, soaRecord.Minimum)
	}

	return "No SOA record found"
}
