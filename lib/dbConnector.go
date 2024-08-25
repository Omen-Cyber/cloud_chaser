/*
Copyright © 2024 ak ak@omencyber.io
*/

package lib

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
