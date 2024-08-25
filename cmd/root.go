/*
Copyright © 2024 ak ak@omencyber.io
*/
package cmd

import (
	_ "github.com/Omen-Cyber/cloud_chaser/runners"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "cloud_chaser",
	Short: "Chase the holes in the clouds",
	Long:  `Just Checking :)`,
}

var (
	scanDomain string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&scanDomain, "domain", "d", "root domain to be scanned")
	rootCmd.MarkFlagRequired("domain")
	rootCmd.SetVersionTemplate(`v0.1`)

}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
