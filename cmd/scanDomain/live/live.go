/*
Copyright © 2024 ak ak@omencyber.io
*/
package live

import (
	"github.com/Omen-Cyber/cloud_chaser/runners/liveScanner"
	"github.com/spf13/cobra"
)

var (
	domain2Scan string
)

// LiveCmd represents the live command
var LiveCmd = &cobra.Command{
	Use:   "live",
	Short: "Probe subdomains for liveness",
	Long:  `Check if subdomains are alive and extract metadata`,
	Run: func(cmd *cobra.Command, args []string) {
		liveScanner.LiveScan([]string{domain2Scan})
	},
}

func init() {
	LiveCmd.PersistentFlags().StringVar(&domain2Scan, "domain", "", "root domain to be scanned")
	LiveCmd.MarkFlagRequired("domain")
}
