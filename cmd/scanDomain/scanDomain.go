/*
Copyright © 2024 ak ak@omencyber.io
*/
package scanDomain

import (
	"fmt"
	"github.com/Omen-Cyber/cloud_chaser/cmd/scanDomain/dns"
	"github.com/spf13/cobra"
)

var (
	domain2Scan string
)

// ScanDomainCmd represents the scanDomain command
var ScanDomainCmd = &cobra.Command{
	Use:   "scanDomain",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("scanDomain called: " + domain2Scan)
	},
}

func init() {
	ScanDomainCmd.PersistentFlags().StringVar(&domain2Scan, "domain", "", "root domain to be scanned")
	ScanDomainCmd.MarkFlagRequired("domain")
	ScanDomainCmd.AddCommand(dns.DnsCmd)

}
