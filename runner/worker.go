package runner

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os/exec"
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
	// Implementation for matching the response body
}

func hasNonVulnerableIndicators(fp Fingerprint) bool {
	return fp.NXDomain
}

func confirmsVulnerability(body string, fp Fingerprint) bool {
	// Implementation to confirm vulnerability based on the response body
}
