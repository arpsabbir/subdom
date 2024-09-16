package runner

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"regexp"
	"github.com/logrusorgru/aurora"
)

type resultStatus string

const (
	ResultCNAME         resultStatus = "cname"
	ResultNotVulnerable resultStatus = "not vulnerable"
	ResultVulnerable    resultStatus = "vulnerable"
)

type Result struct {
	ResStatus    resultStatus
	Status       aurora.Value
	Entry        Fingerprint
	ResponseBody string
}

// checkSubdomain checks the given subdomain for CNAME records and matches with fingerprints.
func (c *Config) checkSubdomain(subdomain string) Result {
	cname, err := getCNAMERecord(subdomain)
	if err != nil {
		return Result{ResStatus: ResultCNAME, Status: aurora.Red("CNAME ERROR"), ResponseBody: err.Error()}
	}

	if cname != "" && cname != subdomain {
		fmt.Printf("CNAME for %s: %s\n", subdomain, cname)
		return c.matchCNAMEWithFingerprints(cname)
	}

	// If no CNAME, use the original subdomain
	return c.matchCNAMEWithFingerprints(subdomain)
}

// getCNAMERecord performs the dig command to get the CNAME record for a single subdomain.
func getCNAMERecord(subdomain string) (string, error) {
	cmd := exec.Command("dig", "+short", "CNAME", subdomain)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing dig command for %s: %v, stderr: %s", subdomain, err, stderr.String())
	}

	cname := strings.TrimSpace(out.String())
	if cname == "" {
		return "No CNAME record found", nil
	}

	return cname, nil
}

// matchCNAMEWithFingerprints checks if the CNAME matches any fingerprints.
func (c *Config) matchCNAMEWithFingerprints(cname string) Result {
	for _, fp := range c.fingerprints {
		if strings.Contains(cname, fp.Fingerprint) {
			if confirmsVulnerability(cname, fp) {
				return Result{
					ResStatus:    ResultVulnerable,
					Status:       aurora.Green("VULNERABLE"),
					Entry:        fp,
					ResponseBody: cname,
				}
			}
			if hasNonVulnerableIndicators(fp) {
				return Result{
					ResStatus:    ResultNotVulnerable,
					Status:       aurora.Red("NOT VULNERABLE"),
					Entry:        fp,
					ResponseBody: cname,
				}
			}
		}
	}
	return Result{
		ResStatus:    ResultNotVulnerable,
		Status:       aurora.Red("NOT VULNERABLE"),
		Entry:        Fingerprint{},
		ResponseBody: cname,
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
			fmt.Printf("Error compiling regex for fingerprint %s: %v", fp.Fingerprint, err)
			return false
		}
		if re.MatchString(body) {
			return true
		}
	}

	return false
}
