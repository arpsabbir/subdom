package runner

import (
	"fmt"
	"os/exec"
	"strings"
	"github.com/logrusorgru/aurora"
	"regexp"
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

// checkSubdomain checks the given subdomain for CNAME records using dig and matches with fingerprints.
func (c *Config) checkSubdomain(subdomain string) Result {
	fmt.Printf("[DEBUG] Checking subdomain: %s\n", subdomain)
	
	cname, err := c.getCNAMEWithDig(subdomain)
	if err != nil {
		fmt.Printf("[ERROR] Failed to get CNAME for %s: %v\n", subdomain, err)
		return Result{ResStatus: ResultCNAME, Status: aurora.Red("CNAME ERROR"), Entry: Fingerprint{}}
	}

	fmt.Printf("[DEBUG] CNAME for %s: %s\n", subdomain, cname)

	if cname != "" && cname != subdomain {
		return c.matchCNAMEWithFingerprints(cname)
	}

	// If no CNAME, use the original subdomain
	return c.matchCNAMEWithFingerprints(subdomain)
}

// getCNAMEWithDig executes the dig command to get the CNAME record.
func (c *Config) getCNAMEWithDig(subdomain string) (string, error) {
	fmt.Printf("[DEBUG] Executing dig command for subdomain: %s\n", subdomain)
	cmd := exec.Command("dig", "+short", "CNAME", subdomain)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[ERROR] Error executing dig command: %v\n", err)
		return "", err
	}

	cname := strings.TrimSpace(string(output))
	fmt.Printf("[DEBUG] Raw dig output: %s\n", string(output))
	fmt.Printf("[DEBUG] Parsed CNAME: %s\n", cname)
	return cname, nil
}

// matchCNAMEWithFingerprints checks if the CNAME matches any fingerprints.
func (c *Config) matchCNAMEWithFingerprints(cname string) Result {
	fmt.Printf("[DEBUG] Matching CNAME %s with fingerprints\n", cname)
	for _, fp := range c.fingerprints {
		fmt.Printf("[DEBUG] Checking fingerprint: %s\n", fp.Fingerprint)
		if strings.Contains(cname, fp.Fingerprint) {
			fmt.Printf("[DEBUG] Found matching fingerprint: %s\n", fp.Fingerprint)
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
	fmt.Printf("[DEBUG] No matching fingerprints found for CNAME %s\n", cname)
	return Result{
		ResStatus:    ResultNotVulnerable,
		Status:       aurora.Red("NOT VULNERABLE"),
		Entry:        Fingerprint{},
		ResponseBody: cname,
	}
}

func hasNonVulnerableIndicators(fp Fingerprint) bool {
	fmt.Printf("[DEBUG] Checking non-vulnerable indicators for fingerprint: %s\n", fp.Fingerprint)
	return fp.NXDomain
}

func confirmsVulnerability(cname string, fp Fingerprint) bool {
	fmt.Printf("[DEBUG] Checking if CNAME %s confirms vulnerability with fingerprint: %s\n", cname, fp.Fingerprint)
	if fp.NXDomain {
		return false
	}

	if fp.Fingerprint != "" {
		re, err := regexp.Compile(fp.Fingerprint)
		if err != nil {
			fmt.Printf("[ERROR] Error compiling regex for fingerprint %s: %v\n", fp.Fingerprint, err)
			return false
		}
		if re.MatchString(cname) {
			fmt.Printf("[DEBUG] CNAME %s matches regex for fingerprint: %s\n", cname, fp.Fingerprint)
			return true
		}
	}

	return false
}
