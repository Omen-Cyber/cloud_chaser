/*
Copyright © 2024 ak ak@omencyber.io
*/
package liveScanner

import (
	"github.com/Omen-Cyber/cloud_chaser/lib/utils"
	"github.com/Omen-Cyber/cloud_chaser/tools/httpx"
)

func LiveScan(domains []string) {
	liveHosts := httpx.Scan(domains)
	utils.SaveHostInfo(liveHosts)
}
