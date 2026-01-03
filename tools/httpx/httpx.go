/*
Copyright © 2024 ak ak@omencyber.io
*/
package httpx

import (
	"fmt"
	"github.com/Omen-Cyber/cloud_chaser/lib/datatypes"
	"github.com/projectdiscovery/httpx/runner"
	"strings"
	"log"
)

func Scan(domains []string) []datatypes.HostInfo {
	var liveHosts []datatypes.HostInfo

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: domains,
		OnResult: func(r runner.Result) {
			if r.Error != "" {
				return
			}
			host := datatypes.HostInfo{
				Domain:       r.Input,
				SubDomain:    r.URL,
				IpAddress:    r.HostIP,
				Alive:        "True",
				Tool:         "httpx",
				Technologies: strings.Join(r.Technologies, ","),
				Directories:  "None",
				Vulnerabilities: "None",
			}
			fmt.Printf("[+] Found Alive Host: %s (%s) [%s]\n", r.URL, r.HostIP, strings.Join(r.Technologies, ","))
			liveHosts = append(liveHosts, host)
		},
		Threads:      50,
		Timeout:      10,
		ExtractTitle: true,
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatalf("failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	return liveHosts
}
