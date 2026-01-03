/*
Copyright © 2024 ak ak@omencyber.io
*/

package utils

import (
	"cloud.google.com/go/bigquery"
	"context"
	"fmt"
	"github.com/Omen-Cyber/cloud_chaser/lib/datatypes"
)

/*
func connect_to_rds() row struct {

	// Define the connection string

	// Open a connection to the database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	insertSQL := `INSERT INTO subdomains
			(root_domain, domain, sub_domain) VALUES (?, ?, ?)`
	_, err = db.Exec(insertSQL, rootDomain, domain, subdomain)
	if err != nil {
		log.Fatal(err)
	}
}
*/

func SaveHostInfo(hosts []datatypes.HostInfo) error {
	projectID := "red-stuff-433205"
	datasetID := "cloud_scanning"
	tableID := "cloud_chaser_host_info"

	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("Skipping BigQuery (Credentials missing or invalid): %v", err)
	}
	defer client.Close()

	if len(hosts) == 0 {
		return nil
	}

	u := client.Dataset(datasetID).Table(tableID).Uploader()
	if err := u.Put(ctx, hosts); err != nil {
		return fmt.Errorf("uploader.Put: %v", err)
	}

	return nil
}
