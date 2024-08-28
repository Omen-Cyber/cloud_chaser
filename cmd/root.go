/*
Copyright © 2024 ak ak@omencyber.io
*/
package cmd

import (
	"github.com/Omen-Cyber/cloud_chaser/cmd/scanDomain"
	_ "github.com/Omen-Cyber/cloud_chaser/runners"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "cloud_chaser",
	Short: "Chase the holes in the clouds",
	Long:  `Just Checking :)`,
}

func init() {
	rootCmd.SetVersionTemplate(`v0.1`)
	rootCmd.AddCommand(scanDomain.ScanDomainCmd)
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
