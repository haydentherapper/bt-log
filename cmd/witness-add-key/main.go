package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"flag"
	"log"

	"github.com/haydentherapper/bt-log/pkg/note"

	_ "github.com/mattn/go-sqlite3" // Import the SQLite driver
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

	pubKey, err := note.GetKeyFile(*pubKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	v, err := note.GetNoteVerifier(*pubKeyFile, "LOG_PUBLIC_KEY")
	if err != nil {
		log.Fatal(err)
	}

	// root hash for empty merkle tree
	emptyRoot := sha256.Sum256([]byte{})

	r, err := db.Exec("INSERT INTO tlog (origin, public_key, tree_size, tree_hash) VALUES (?, ?, ?, ?)",
		v.Name(), pubKey, 0, base64.RawStdEncoding.EncodeToString(emptyRoot[:]))
	if err != nil {
		log.Fatal(err)
	}
	if c, err := r.RowsAffected(); err != nil {
		log.Fatal(err)
	} else if c != 1 {
		log.Fatalf("expected one new row, inserted %d new rows", c)
	}
}
