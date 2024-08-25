package tools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strings"
)

func sublister_scan(domain string) {

	var scanned_subdomains []host_info

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
			var temp_domain_struct = extract_subdomain(s)
			scanned_subdomains = append(scanned_subdomains, *temp_domain_struct)
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

	for _, domains := range scanned_subdomains {
		fmt.Printf("Subdomain %s: %s\n", domains.subDomain, domains.tool)
	}
}

func extract_subdomain(uno_domain *resolve.HostEntry) *host_info {

	domain_info := new(host_info)

	domain_slice := uno_domain

	//fmt.Println("FOUND New Subdomain: " + uno_domain.Domain)

	//Validate we are dealing with a true subdomain
	parts := strings.Split(domain_slice.Host, ".")

	if len(parts) >= 2 {
		domain_info.rootDomain = parts[len(parts)-2] + "." + parts[len(parts)-1]
	} else {
		log.Fatal("Invalid subdomain string")
	}

	//Adding the root domain
	domain_info.rootDomain = domain_slice.Domain
	//adding the whole domain
	domain_info.domain = domain_slice.Host
	//Adding subdomain
	domain_info.subDomain = strings.Join(parts[:len(parts)-2], ".")
	//adding tool
	domain_info.tool = domain_slice.Source
	//domain_info.ipAddress = domain_slice.ipAddress
	//domain_info.directories = domain_slice.ipAddress

	return domain_info

}
