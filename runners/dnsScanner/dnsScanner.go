/*
Copyright © 2024 ak ak@omencyber.io
*/
package dnsScanner

import (
	"github.com/Omen-Cyber/cloud_chaser/tools/subfinder"
)

func DnsScan(scanDomain string) {
	subfinder.Scan(scanDomain)
}
