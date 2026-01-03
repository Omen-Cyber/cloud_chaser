/*
Copyright © 2024 ak ak@omencyber.io
*/
package reconScanner

import (
	"fmt"
	"github.com/Omen-Cyber/cloud_chaser/tools/httpx"
	"github.com/Omen-Cyber/cloud_chaser/tools/subfinder"
)

func ReconScan(domain string) {
	fmt.Printf("Starting full recon for %s...\n", domain)

	// Step 1: Subdomain Enumeration
	fmt.Println("[+] Running Subfinder...")
	subdomains := subfinder.Scan(domain)

	// Step 2: Extract domains for httpx
	var domainStrings []string
	for _, s := range subdomains {
		domainStrings = append(domainStrings, s.Domain)
	}

	// Step 3: Web Probing
	if len(domainStrings) > 0 {
		fmt.Printf("[+] Running httpx on %d subdomains...\n", len(domainStrings))
		httpx.Scan(domainStrings)
	} else {
		fmt.Println("[-] No subdomains found to probe.")
	}

	fmt.Println("[+] Recon complete.")
}
