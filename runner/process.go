package runner

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
)

// Process orchestrates the subdomain checking process.
func Process(config *Config) error {
	// Load fingerprints from file
	fingerprints, err := Fingerprints()
	if err != nil {
		return fmt.Errorf("Process: %v", err)
	}

	// Initialize HTTP client and load fingerprints into the config
	config.initHTTPClient()
	config.loadFingerprints()

	// Get list of subdomains
	subdomains := getSubdomains(config)

	fmt.Println("[ * ] Loaded", len(subdomains), "targets")
	fmt.Println("[ * ] Loaded", len(fingerprints), "fingerprints")

	// Print configuration details
	if config.Output != "" {
		fmt.Printf("[ * ] Output filename: %s\n", config.Output)
		fmt.Println(isEnabled(config.OnlyVuln), "Save only vulnerable subdomains")
	}
	fmt.Println(isEnabled(config.HTTPS), "HTTPS by default (--https)")
	fmt.Println("[", config.Concurrency, "]", "Concurrent requests (--concurrency)")
	fmt.Println(isEnabled(config.VerifySSL), "Check target only if SSL is valid (--verify_ssl)")
	fmt.Println("[", config.Timeout, "]", "HTTP request timeout (in seconds) (--timeout)")
	fmt.Println(isEnabled(config.HideFails), "Show only potentially vulnerable subdomains (--hide_fails)")

	// Channels for distributing subdomains and collecting results
	const ExtraChannelCapacity = 5
	subdomainCh := make(chan string, config.Concurrency+ExtraChannelCapacity)
	resCh := make(chan *subdomainResult, config.Concurrency)

	var wg sync.WaitGroup
	wg.Add(config.Concurrency)

	var results []*subdomainResult
	go collectResults(resCh, &results, config)

	// Start worker goroutines
	for i := 0; i < config.Concurrency; i++ {
		go processor(subdomainCh, resCh, config, &wg)
	}

	// Distribute subdomains to the channel
	distributeSubdomains(subdomains, subdomainCh)

	// Wait for all workers to finish
	wg.Wait()
	close(resCh)

	// Save results if an output file is specified
	if config.Output != "" {
		if err := saveResults(config.Output, results); err != nil {
			return err
		}
	}

	return nil
}

// processor processes subdomains and sends results to resCh.
func processor(subdomainCh <-chan string, resCh chan<- *subdomainResult, c *Config, wg *sync.WaitGroup) {
	defer wg.Done()
	for subdomain := range subdomainCh {
		// Here, you need to handle the subdomain request appropriately
		// Assuming a function `checkSubdomain` handles the subdomain directly

		result := c.checkSubdomain(subdomain) // Check the subdomain, adjust as needed

		res := &subdomainResult{
			Subdomain:     subdomain,
			Status:        string(result.ResStatus),
			Engine:        result.Entry.Service,
			Documentation: result.Entry.Documentation,
		}

		if result.Status == aurora.Green("VULNERABLE") {
			fmt.Print("-----------------\n")
			fmt.Println("[", result.Status, "]", " - ", subdomain, " [", result.Entry.Service, "]")
			fmt.Println("[", aurora.Blue("DISCUSSION"), "]", " - ", result.Entry.Discussion)
			fmt.Println("[", aurora.Blue("DOCUMENTATION"), "]", " - ", result.Entry.Documentation)
			fmt.Print("-----------------\n")
		} else {
			if !c.HideFails {
				fmt.Println("[", result.Status, "]", " - ", subdomain)
			}
		}

		resCh <- res
	}
}

// distributeSubdomains sends subdomains to a channel, removing any leading/trailing whitespace.
func distributeSubdomains(subdomains []string, subdomainCh chan<- string) {
	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(subdomain) // Remove any leading/trailing whitespace
		if subdomain != "" {
			subdomainCh <- subdomain
		}
	}
	close(subdomainCh)
}

// collectResults gathers results from resCh and stores them in the results slice.
func collectResults(resCh <-chan *subdomainResult, results *[]*subdomainResult, config *Config) {
	for r := range resCh {
		if config.Output != "" && (!config.OnlyVuln || r.Status == "VULNERABLE") {
			*results = append(*results, r)
		}
	}
}

// saveResults saves the results to the specified output file.
func saveResults(filename string, results []*subdomainResult) error {
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		return err
	}

	fmt.Printf("[ * ] Saved output to %q\n", filename)
	return nil
}

// getSubdomains retrieves subdomains from the configuration.
func getSubdomains(c *Config) []string {
	if c.Target == "" {
		subdomains, err := readSubdomains(c.Targets)
		if err != nil {
			log.Fatalf("Error reading subdomains: %s", err)
		}
		return subdomains
	}
	return strings.Split(c.Target, ",")
}
