package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/haydentherapper/bt-log/internal/db/postgres"
	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var (
	host        = flag.String("host", "localhost", "host to listen on")
	port        = flag.Uint("port", 8081, "port to listen on")
	dbPath      = flag.String("database-path", "", "path to checkpoint database (for sqlite)")
	privKeyFile = flag.String("private-key", "", "location of witness private key file")
	pubKeyFile  = flag.String("public-key", "", "location of witness public key file")
	dbType      = flag.String("db-type", "sqlite", "database type (sqlite, mysql, postgres)")
	dbDSN       = flag.String("db-dsn", "", "database data source name")
)

func writeCosignatureResp(w http.ResponseWriter, cosignedCheckpoint []byte) {
	// Split co-signed checkpoint to extract signatures
	_, sigs, ok := bytes.Cut(cosignedCheckpoint, []byte("\n\n"))
	if !ok {
		log.Printf("error splitting cosigned checkpoint\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Remove first signature line, which is the log signature
	_, cosig, ok := bytes.Cut(sigs, []byte("\n"))
	if !ok {
		log.Printf("error splitting signatures on checkpoint\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return cosignature
	if _, err := w.Write(cosig); err != nil {
		log.Printf("/add-checkpoint: %v", err)
	}
}

func main() {
	flag.Parse()

	if (*dbPath == "" && *dbDSN == "") || (*dbPath != "" && *dbDSN != "") {
		log.Fatalf("exactly one of --database-path or --db-dsn must be set")
	}
	if *dbPath != "" && *dbType != "sqlite" {
		log.Fatalf("--database-path can only be used with --db-type=sqlite")
	}
	if *privKeyFile == "" {
		log.Fatalf("--private-key required to initialize witness")
	}
	if *pubKeyFile == "" {
		log.Fatalf("--public-key required to initialize witness")
	}

	var driverName, dsn string
	rebind := func(s string) string { return s } // Default is no-op for mysql and sqlite

	switch *dbType {
	case "sqlite":
		driverName = "sqlite"
		if *dbDSN != "" {
			dsn = *dbDSN
		} else {
			// Enable Write-Ahead Logging for better concurrency, allowing reads during writes.
			// A busy timeout is also set to prevent "database is locked" errors under contention,
			// with writers waiting 1s before returning an error.
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
		log.Fatalf("failed to open database: %v", err)
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

	// Initialize witness note signer
	privKey, err := os.ReadFile(*privKeyFile)
	if err != nil {
		log.Fatalf("failed to read private key file for %s: %v", *privKeyFile, err)
	}
	witnessSigner, err := note.NewSigner(string(privKey))
	if err != nil {
		log.Fatalf("failed to read signer %s: %v", *privKeyFile, err)
	}

	// C2SP requires a submission prefix for add-checkpoint
	// Tessera expects this to be the witness public key hash
	pubKey, err := os.ReadFile(*pubKeyFile)
	if err != nil {
		log.Fatalf("failed to read public key file for %s: %v", *pubKeyFile, err)
	}
	key64 := strings.SplitAfterN(string(pubKey), "+", 3)[2]
	key, err := base64.StdEncoding.DecodeString(key64)
	if err != nil {
		log.Fatalf("failed to parse witness public key: %v", err)
	}
	h := sha256.Sum256(key)

	// Request body must be:
	// - an old size line,
	// - zero or more consistency proof lines,
	// - and an empty line,
	// - followed by a checkpoint
	http.HandleFunc(fmt.Sprintf("POST /%x/add-checkpoint", h), func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Split the consistency proof and signed note (checkpoint)
		cProof, signedNote, ok := bytes.Cut(b, []byte("\n\n"))
		if !ok {
			log.Printf("error splitting consistency proof and signed note\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Split the consistency proof into a size line and proof lines
		lines := strings.Split(string(cProof), "\n")
		if len(lines) == 0 {
			log.Printf("error splitting consistency proof\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// First line must match "old <size>" where <size> is the last witnessed log size
		oldAndSize := strings.Split(lines[0], " ")
		if len(oldAndSize) != 2 {
			log.Printf("error splitting old log size\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if oldAndSize[0] != "old" {
			log.Printf("error, no old string\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		oldSize, err := strconv.ParseUint(oldAndSize[1], 10, 0)
		if err != nil {
			log.Printf("error parsing old size\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Parse base64-encoded consistency proof lines
		var consistencyProof [][]byte
		for _, c := range lines[1:] {
			rawProof, err := base64.StdEncoding.DecodeString(c)
			if err != nil {
				log.Printf("error decoding proof: %v\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			consistencyProof = append(consistencyProof, rawProof)
		}

		// Get log origin from first line of checkpoint
		var origin string
		if lines := strings.Split(string(signedNote), "\n"); len(lines) == 0 {
			log.Printf("error splitting signed note to extract origin\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		} else {
			origin = lines[0]
		}

		// Lookup log verifier, size and hash for the given origin
		query := rebind("SELECT public_key, tree_size, tree_hash FROM tlog WHERE origin = ?")
		rows, err := db.Query(query, origin)
		if err != nil {
			log.Printf("error querying database by origin: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// At most one row will be selected since origin is a primary key
		var publicKey string
		var treeSize uint64
		var treeHashB64 string
		for rows.Next() {
			if err := rows.Scan(&publicKey, &treeSize, &treeHashB64); err != nil {
				log.Printf("error scanning row: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		// If public key is empty, no row was selected, so the origin is unknown
		if publicKey == "" {
			// Return 404 for unknown log
			log.Printf("origin %s not known by witness\n", origin)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		treeHash, err := base64.StdEncoding.DecodeString(treeHashB64)
		if err != nil {
			log.Printf("error parsing tree hash: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Load verifier for log checkpoint
		v, err := note.NewVerifier(publicKey)
		if err != nil {
			log.Printf("error parsing log public key: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Verify log checkpoint
		newCp, _, newCpNote, err := tlog.ParseCheckpoint(signedNote, v.Name(), v)
		if err != nil {
			// Return 403 for unverifiable checkpoint (e.g. invalid key for a given origin)
			log.Printf("error parsing log checkpoint: %v\n", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Old size must be equal or lower than the checkpoint size
		if oldSize > newCp.Size {
			// Return 400 if old size is greater than checkpoint size
			log.Printf("old size must be less than or equal to the new size\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if oldSize != treeSize {
			// Return 409 if old size does not match last verified size,
			// and return the current size in a header
			// A log may send 0 as the old size if the log does not know the current state
			// of the witness
			log.Printf("old size %d and last verified size %d must match\n", oldSize, treeSize)
			w.Header().Set("Content-Type", "text/x.tlog.size")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(fmt.Sprintf("%d", treeSize)))
			return
		}
		if oldSize == newCp.Size && !reflect.DeepEqual(treeHash, newCp.Hash) {
			// Return 409 if the old size and checkpoint size match but the root hashes don't
			log.Println("checkpoint and previous size match, but root hashes don't")
			w.WriteHeader(http.StatusConflict)
			return
		}

		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, oldSize, newCp.Size, consistencyProof, treeHash, newCp.Hash); err != nil {
			// Return 422 if the consistency proof does not verify
			log.Printf("proof did not verify: %v\n", err)
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		// Co-sign checkpoint
		cosignedCheckpoint, err := note.Sign(newCpNote, witnessSigner)
		if err != nil {
			log.Printf("error cosigning checkpoint: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// If the checkpoint is identical to what we've already seen, return the cosigned checkpoint.
		// This is necessary since MySQL's RowsAffected behavior for no-op UPDATEs is different
		// than other databases and won't register an update if the column values are identical.
		if oldSize == newCp.Size && reflect.DeepEqual(treeHash, newCp.Hash) {
			writeCosignatureResp(w, cosignedCheckpoint)
			return
		}

		// Persist verified size and hash. Only update where tree_size matches the last verified size,
		// to prevent concurrent requests from rolling back the witness state
		updateQuery := rebind("UPDATE tlog SET tree_size = ?, tree_hash = ? WHERE origin = ? AND tree_size = ?")
		if r, err := db.Exec(updateQuery,
			newCp.Size, base64.StdEncoding.EncodeToString(newCp.Hash), origin, oldSize); err != nil {
			log.Printf("error updating stored checkpoint: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if c, err := r.RowsAffected(); err != nil {
			log.Printf("error reading rows after storing checkpoint: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if c != 1 {
			// If the witness has not updated a row, then a concurrent request must fail.
			// Return a 409 with the new verified size
			selectQuery := rebind("SELECT tree_size FROM tlog WHERE origin = ?")
			rows, err := db.Query(selectQuery, origin)
			if err != nil {
				log.Printf("error reading latest size: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var treeSize uint64
			for rows.Next() {
				if err := rows.Scan(&treeSize); err != nil {
					log.Printf("error reading tree size from returned row: %v\n", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}

			w.Header().Set("Content-Type", "text/x.tlog.size")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(fmt.Sprintf("%d", treeSize)))
			return
		}

		writeCosignatureResp(w, cosignedCheckpoint)
	})

	address := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Server running on %s\n", address)

	if err := http.ListenAndServe(address, http.DefaultServeMux); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
