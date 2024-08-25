/*
Copyright © 2024 ak ak@omencyber.io
*/
package cmd

import (
	"fmt"
	_ "github.com/Omen-Cyber/cloud_chaser/runners"
	"github.com/spf13/cobra"
)

// dnsCmd represents the dns command
var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "A brief description of your command",
	Long:  `Doing DNS things`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("dns called")
	},
}

func init() {
	scanDomainCmd.AddCommand(dnsCmd)
	rootCmd.AddCommand(dnsCmd)
	dnsScanner.dnsScan(scanDomain)
}
