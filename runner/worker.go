package runner

import (
	"bytes"
	"io"
	"log"
	"os/exec"
	"strings"

	"github.com/logrusorgru/aurora"
)

type resultStatus string

const (
	ResultHTTPError     resultStatus = "http error"
	ResultResponseError resultStatus = "response error"
	ResultVulnerable    resultStatus = "vulnerable"
	ResultNotVulnerable resultStatus = "not vulnerable"
	ResultNotFound      resultStatus = "not found"
)

type Result struct {
	ResStatus    resultStatus
	Status       aurora.Value
	Entry        Fingerprint
	ResponseBody string
}

func (c *Config) checkSubdomain(subdomain string) Result {
	// Perform dig command to check if subdomain exists
	if !c.checkDNSRecord(subdomain) {
		return Result{ResStatus: ResultNotFound, Status: aurora.Red("NOT FOUND"), Entry: Fingerprint{}, ResponseBody: ""}
	}

	url := subdomain
	if !isValidUrl(url) {
		if c.HTTPS {
			url = "https://" + subdomain
		} else {
			url = "http://" + subdomain
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

func (c *Config) checkDNSRecord(subdomain string) bool {
	// Execute dig command to check if subdomain has DNS records
	cmd := exec.Command("dig", "+short", subdomain)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("Error executing dig command: %v", err)
		return false
	}

	// Check if output contains any records
	output := out.String()
	return strings.TrimSpace(output) != ""
}

func (c *Config) matchResponse(body string) Result {
	// Placeholder implementation
	// You need to implement this function based on your specific needs
	return Result{ResStatus: ResultNotVulnerable, Status: aurora.Green("NO VULNERABILITY DETECTED"), Entry: Fingerprint{}, ResponseBody: body}
}

func hasNonVulnerableIndicators(fp Fingerprint) bool {
	return fp.NXDomain
}

func confirmsVulnerability(body string, fp Fingerprint) bool {
	// Placeholder implementation
	// You need to implement this function based on your specific needs
	return false
}

// Utility function to validate URLs (you might need to implement this)
func isValidUrl(url string) bool {
	// Placeholder URL validation
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}
