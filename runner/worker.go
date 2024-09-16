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
	ResultCNAME        resultStatus = "cname"
)

type Result struct {
	ResStatus    resultStatus
	Status       aurora.Value
	Entry        Fingerprint
	ResponseBody string
}

// checkSubdomain performs a CNAME lookup and then checks for vulnerabilities
func (c *Config) checkSubdomain(subdomain string) Result {
	// Perform the CNAME lookup
	cname, err := net.LookupCNAME(subdomain)
	if err != nil {
		// Handle error if CNAME lookup fails
		fmt.Printf("Error resolving CNAME for %s: %v\n", subdomain, err)
		return Result{ResStatus: ResultCNAME, Status: aurora.Red("CNAME ERROR"), Entry: Fingerprint{}}
	}

	if cname != "" && cname != subdomain {
		fmt.Printf("CNAME for %s: %s\n", subdomain, cname)
		return c.checkURL(cname)
	}

	// If no CNAME, use the original subdomain
	return c.checkURL(subdomain)
}

// checkURL performs HTTP request and matches response with fingerprints.
func (c *Config) checkURL(url string) Result {
	if !isValidUrl(url) {
		if c.HTTPS {
			url = "https://" + url
		} else {
			url = "http://" + url
		}
	}

	resp, err := c.client.Get(url)
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

// matchResponse checks if the response body matches any of the fingerprints.
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

// hasNonVulnerableIndicators checks if a fingerprint indicates non-vulnerability.
func hasNonVulnerableIndicators(fp Fingerprint) bool {
	return fp.NXDomain
}

// confirmsVulnerability checks if the response body matches the fingerprint criteria.
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

