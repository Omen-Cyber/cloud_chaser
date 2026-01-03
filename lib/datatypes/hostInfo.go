/*
Copyright © 2024 ak ak@omencyber.io
*/
package datatypes

type HostInfo struct {
	RootDomain      string `bigquery:"root_domain"`
	Domain          string `bigquery:"domain"`
	SubDomain       string `bigquery:"subdomain"`
	IpAddress       string `bigquery:"ip_address"`
	Directories     string `bigquery:"directories"`
	Alive           string `bigquery:"alive"`
	Tool            string `bigquery:"tool"`
	Vulnerabilities string `bigquery:"vulnerabilities"`
	Technologies    string `bigquery:"technologies"`
}
