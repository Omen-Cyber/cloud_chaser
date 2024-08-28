/*
Copyright © 2024 ak ak@omencyber.io
*/
package dns

import (
	"github.com/Omen-Cyber/cloud_chaser/runners/dnsScanner"
	"github.com/spf13/cobra"
)

var (
	domain2Scan string
)

// DnsCmd represents the dns command
var DnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "A brief description of your command",
	Long:  `Doing DNS things`,
	Run: func(cmd *cobra.Command, args []string) {
		dnsScanner.DnsScan(domain2Scan)
	},
}

func init() {
	DnsCmd.PersistentFlags().StringVar(&domain2Scan, "domain", "", "root domain to be scanned")
	DnsCmd.MarkFlagRequired("domain")

}
