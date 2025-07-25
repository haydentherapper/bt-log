package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/haydentherapper/bt-log/internal/db/postgres"
	"golang.org/x/mod/sumdb/note"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var (
	dbPath     = flag.String("database-path", "", "Path to checkpoint database (for sqlite)")
	pubKeyFile = flag.String("public-key", "", "Location of public key file")
	dbType     = flag.String("db-type", "sqlite", "database type (sqlite, mysql, postgres)")
	dbDSN      = flag.String("db-dsn", "", "database data source name")
)

func main() {
	flag.Parse()

	if (*dbPath == "" && *dbDSN == "") || (*dbPath != "" && *dbDSN != "") {
		log.Fatalf("exactly one of --database-path or --db-dsn must be set")
	}
	if *dbPath != "" && *dbType != "sqlite" {
		log.Fatalf("--database-path can only be used with --db-type=sqlite")
	}
	if *pubKeyFile == "" {
		log.Fatalf("--public-key required to add log key to witness")
	}

	var driverName, dsn string
	rebind := func(s string) string { return s } // Default is no-op for mysql and sqlite

	switch *dbType {
	case "sqlite":
		driverName = "sqlite"
		if *dbDSN != "" {
			dsn = *dbDSN
		} else {
			dsn = fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=1000", *dbPath)
		}
	case "mysql":
		driverName = "mysql"
		if *dbDSN == "" {
			log.Fatalf("--db-dsn must be set for --db-type=mysql")
		}
		dsn = *dbDSN
	case "postgres":
		driverName = "pgx"
		if *dbDSN == "" {
			log.Fatalf("--db-dsn must be set for --db-type=postgres")
		}
		dsn = *dbDSN
		rebind = postgres.Rebind
	default:
		log.Fatalf("unsupported --db-type: %s. Must be one of 'sqlite', 'mysql', 'postgres'", *dbType)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create the table (if it doesn't already exist)
	_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS tlog (
					origin VARCHAR(255) PRIMARY KEY,
					public_key TEXT NOT NULL, -- note verifier format
					tree_size INTEGER NOT NULL,
					tree_hash TEXT NOT NULL -- base64-encoded
			)
	`)
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := os.ReadFile(*pubKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	v, err := note.NewVerifier(string(pubKey))
	if err != nil {
		log.Fatalf("failed to read verifier %s: %v", *pubKeyFile, err)
	}

	// Check if the origin (primary key) already exists
	var count int
	query := rebind("SELECT COUNT(*) FROM tlog WHERE origin = ?")
	err = db.QueryRow(query, v.Name()).Scan(&count)
	if err != nil {
		log.Fatalf("failed to check for existing origin: %v", err)
	}
	if count > 0 {
		log.Printf("Origin '%s' already exists. Skipping.", v.Name())
		return
	}

	// root hash for empty merkle tree
	emptyRoot := sha256.Sum256([]byte{})

	insertQuery := rebind("INSERT INTO tlog (origin, public_key, tree_size, tree_hash) VALUES (?, ?, ?, ?)")
	r, err := db.Exec(insertQuery,
		v.Name(), string(pubKey), 0, base64.StdEncoding.EncodeToString(emptyRoot[:]))
	if err != nil {
		log.Fatal(err)
	}
	if c, err := r.RowsAffected(); err != nil {
		log.Fatal(err)
	} else if c != 1 {
		log.Fatalf("expected one new row, inserted %d new rows", c)
	}
}
