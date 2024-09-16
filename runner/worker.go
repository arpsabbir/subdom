package runner

import (
	"fmt"
	"net"
	"strings"
)

// checkSubdomain performs DNS checks and HTTP checks on the subdomain.
func (c *Config) checkSubdomain(subdomain string) *subdomainResult {
	result := &subdomainResult{
		Subdomain: subdomain,
	}

	// Check for CNAME record
	cname, err := net.LookupCNAME(subdomain)
	if err != nil {
		result.Status = "DNS ERROR"
		return result
	}

	if cname != "" && cname != subdomain {
		fmt.Printf("CNAME found for %s: %s\n", subdomain, cname)

		// Get root domain from CNAME and perform DNS and SOA checks
		rootDomain := extractRootDomain(cname)
		if rootDomain != "" {
			cnameResult := checkDNSRecordsForCNAME(rootDomain)
			if cnameResult != nil {
				result.Status = "CNAME FOUND"
				result.Engine = "DNS Check"
				result.Documentation = fmt.Sprintf("CNAME: %s, %s", cname, cnameResult)
				return result
			}
		}
	}

	// If CNAME is not found or DNS checks are not conclusive, perform HTTP check
	httpResult := c.checkHTTP(subdomain)
	if httpResult.Status == "OK" {
		result.Status = "VULNERABLE"
		result.Engine = "HTTP Check"
		return result
	}

	result.Status = "NOT VULNERABLE"
	return result
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

// extractRootDomain extracts the root domain from a CNAME record.
func extractRootDomain(cname string) string {
	// Assume CNAME follows the format: subdomain.targetdomain.com.
	// Extract the root domain from the CNAME.
	parts := strings.Split(cname, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return ""
}

// checkHTTP performs an HTTP GET request on the subdomain.
func (c *Config) checkHTTP(subdomain string) *subdomainResult {
	url := "http://" + subdomain

	// Timeout for HTTP request
	client := &http.Client{
		Timeout: time.Duration(c.Timeout) * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return &subdomainResult{
			Subdomain: subdomain,
			Status:    "HTTP ERROR",
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return &subdomainResult{
			Subdomain: subdomain,
			Status:    "OK",
		}
	}

	return &subdomainResult{
		Subdomain: subdomain,
		Status:    fmt.Sprintf("HTTP ERROR %d", resp.StatusCode),
	}
}
