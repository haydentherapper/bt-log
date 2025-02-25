package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"flag"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3" // Import the SQLite driver
	"golang.org/x/mod/sumdb/note"
)

var (
	dbPath     = flag.String("database-path", "", "Path to checkpoint database")
	pubKeyFile = flag.String("public-key", "", "Location of public key file")
)

func main() {
	flag.Parse()

	if *dbPath == "" {
		log.Fatalf("--database-path required to add log to witness")
	}
	if *pubKeyFile == "" {
		log.Fatalf("--public-key required to add log key to witness")
	}

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create the table (if it doesn't already exist)
	_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS tlog (
					origin TEXT PRIMARY KEY,
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

	// root hash for empty merkle tree
	emptyRoot := sha256.Sum256([]byte{})

	r, err := db.Exec("INSERT INTO tlog (origin, public_key, tree_size, tree_hash) VALUES (?, ?, ?, ?)",
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
