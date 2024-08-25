/*
Copyright © 2024 ak ak@omencyber.io
*/

package tools

import (
	"bytes"
	"context"
	"fmt"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"log"
	"strings"
)

type hostInfo struct {
	rootDomain      string
	domain          string
	subDomain       string
	ipAddress       string
	directories     string
	alive           bool
	tool            string
	vulnerabilities string
}

func extractSubdomain(unoDomain *resolve.HostEntry) *hostInfo {

	domainInfo := new(hostInfo)

	domainSlice := unoDomain

	//fmt.Println("FOUND New Subdomain: " + uno_domain.Domain)

	//Validate we are dealing with a true subdomain
	parts := strings.Split(domainSlice.Host, ".")

	if len(parts) >= 2 {
		domainInfo.rootDomain = parts[len(parts)-2] + "." + parts[len(parts)-1]
	} else {
		log.Fatal("Invalid subdomain string")
	}

	//Adding the root domain
	domainInfo.rootDomain = domainSlice.Domain
	//adding the whole domain
	domainInfo.domain = domainSlice.Host
	//Adding subdomain
	domainInfo.subDomain = strings.Join(parts[:len(parts)-2], ".")
	//adding tool
	domainInfo.tool = domainSlice.Source
	//domain_info.ipAddress = domain_slice.ipAddress
	//domain_info.directories = domain_slice.ipAddress

	return domainInfo

}

func subfinderScan(domain string) {

	var scannedSubdomains []hostInfo

	subfinderOpts := &runner.Options{
		Verbose:            false,
		NoColor:            false,
		JSON:               false,
		HostIP:             true,
		Silent:             true,
		ListSources:        true,
		RemoveWildcard:     false,
		CaptureSources:     false,
		Stdin:              false,
		Version:            false,
		OnlyRecursive:      true,
		All:                false,
		Statistics:         true,
		Threads:            16,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Domain:             nil,
		DomainsFile:        "",
		Output:             nil,
		OutputFile:         "",
		OutputDirectory:    "",
		Sources:            nil,
		ExcludeSources:     nil,
		Resolvers:          nil,
		ResolverList:       "",
		Config:             "",
		ProviderConfig:     "",
		Proxy:              "",
		RateLimit:          0,
		RateLimits:         goflags.RateLimitMap{},
		ExcludeIps:         false,
		Match:              nil,
		Filter:             nil,
		ResultCallback: func(s *resolve.HostEntry) {
			var tempDomainStruct = extractSubdomain(s)
			scannedSubdomains = append(scannedSubdomains, *tempDomainStruct)
		},
		DisableUpdateCheck: false,
	}

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Fatalf("failed to create subfinder runner: %v", err)
	}

	output := &bytes.Buffer{}

	// To run subdomain enumeration on a single domain
	if err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate single domain: %v", err)

	}

	for _, domains := range scannedSubdomains {
		fmt.Printf("Subdomain %s: %s\n", domains.subDomain, domains.tool)
	}
}
