/*
Copyright © 2024 ak ak@omencyber.io
*/

package subfinder

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Omen-Cyber/cloud_chaser/lib/datatypes"
	"github.com/Omen-Cyber/cloud_chaser/lib/utils"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"log"
	"strings"
)

func extractSubdomain(unoDomain *resolve.HostEntry) *datatypes.HostInfo {

	domainInfo := new(datatypes.HostInfo)

	domainSlice := unoDomain

	//fmt.Println("FOUND New Subdomain: " + uno_domain.Domain)

	//Validate we are dealing with a true subdomain
	parts := strings.Split(domainSlice.Host, ".")

	if len(parts) >= 2 {
		domainInfo.RootDomain = parts[len(parts)-2] + "." + parts[len(parts)-1]
	} else {
		log.Fatal("Invalid subdomain string")
	}

	//Adding the root domain
	domainInfo.RootDomain = domainSlice.Domain
	//adding the whole domain
	domainInfo.Domain = domainSlice.Host
	//Adding subdomain
	domainInfo.SubDomain = strings.Join(parts[:len(parts)-2], ".")
	//adding tool
	domainInfo.Tool = domainSlice.Source
	//domain_info.ipAddress = domain_slice.ipAddress
	//domain_info.directories = domain_slice.ipAddress

	return domainInfo

}

func Scan(domain string) {

	var scannedSubdomains []datatypes.HostInfo

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
		fmt.Printf("Subdomain %s: %s\n", domains.SubDomain, domains.Tool)
	}
	erro := utils.BQConnection()
	if erro != nil {
		fmt.Println(erro)
	}

}
