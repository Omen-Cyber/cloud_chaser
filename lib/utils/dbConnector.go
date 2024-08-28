/*
Copyright © 2024 ak ak@omencyber.io
*/

package utils

import (
	"cloud.google.com/go/bigquery"
	"context"
	"fmt"
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

func BQConnection() error {
	projectID := "red-stuff-433205"
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("bigquery.NewClient: %v", err)
	}
	defer client.Close()

	q := client.Query(
		"INSERT cloud_scanning.cloud_chaser_host_info" +
			" (domain,subdomain,root_domain,alive,directories,technologies,tool,ip_address,vulnerabilities) " +
			"VALUES " +
			"('test.com', 'test.test.com','test.com','True','None','None','None','None','None');")

	// Location must match that of the dataset(s) referenced in the query.
	q.Location = "US"
	// Run the query and print results when the query job is completed.
	job, err := q.Run(ctx)
	if err != nil {
		return err
	}
	status, err := job.Wait(ctx)
	if err != nil {
		return err
	}
	if err := status.Err(); err != nil {
		return err
	}
	/*
		it, err := job.Read(ctx)
		for {
			var row []bigquery.Value
			err := it.Next(&row)
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(w, row)
		}

	*/
	return nil
}
