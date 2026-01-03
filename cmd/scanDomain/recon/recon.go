/*
Copyright © 2024 ak ak@omencyber.io
*/
package recon

import (
	"github.com/Omen-Cyber/cloud_chaser/runners/reconScanner"
	"github.com/spf13/cobra"
)

var (
	domain2Scan string
)

// ReconCmd represents the recon command
var ReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Full recon workflow",
	Long:  `Run a full recon workflow: subfinder -> httpx`,
	Run: func(cmd *cobra.Command, args []string) {
		reconScanner.ReconScan(domain2Scan)
	},
}

func init() {
	ReconCmd.PersistentFlags().StringVar(&domain2Scan, "domain", "", "root domain to be scanned")
	ReconCmd.MarkFlagRequired("domain")
}
