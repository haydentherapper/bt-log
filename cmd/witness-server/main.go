package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	noteSV "github.com/haydentherapper/bt-log/pkg/note"
	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	tlog_note "golang.org/x/mod/sumdb/note"

	_ "github.com/mattn/go-sqlite3" // Import the SQLite driver
)

var (
	host               = flag.String("host", "localhost", "host to listen on")
	port               = flag.Uint("port", 8081, "port to listen on")
	dbPath             = flag.String("database-path", "", "Path to checkpoint database")
	witnessPrivKeyFile = flag.String("witness-private-key", "", "Location of private key file. If unset, uses the contents of the WITNESS_PRIVATE_KEY environment variable.")
)

func main() {
	flag.Parse()

	if *dbPath == "" {
		log.Fatalf("--database-path required to initialize witness")
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

	witnessSigner, err := noteSV.GetNoteSigner(*witnessPrivKeyFile, "WITNESS_PRIVATE_KEY")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /add-checkpoint", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Println(string(b))

		cProof, signedNote, ok := bytes.Cut(b, []byte("\n\n"))
		if !ok {
			log.Printf("error splitting consistency proof and signed note\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lines := strings.Split(string(cProof), "\n")
		if len(lines) == 0 {
			log.Printf("error splitting consistency proof\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
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
		var consistencyProof [][]byte
		for _, c := range lines[1:] {
			rawProof, err := base64.RawStdEncoding.DecodeString(c)
			if err != nil {
				log.Printf("error decoding proof: %v\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			consistencyProof = append(consistencyProof, rawProof)
		}

		var origin string
		if lines := strings.Split(string(signedNote), "\n"); len(lines) == 0 {
			log.Printf("error splitting signed note to extract origin\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		} else {
			origin = lines[0]
		}

		// Lookup verifier and hash for previously verified checkpoint
		rows, err := db.Query("SELECT public_key, tree_size, tree_hash FROM tlog WHERE origin = ?", origin)
		if err != nil {
			log.Printf("no log found for origin: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer rows.Close()

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
		treeHash, err := base64.RawStdEncoding.DecodeString(treeHashB64)
		if err != nil {
			log.Printf("error parsing tree hash: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		v, err := note.NewVerifier(publicKey)
		if err != nil {
			log.Printf("error parsing log public key: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		newCp, _, newCpNote, err := tlog.ParseCheckpoint(signedNote, v.Name(), v)
		if err != nil {
			log.Printf("error parsing log checkpoint: %v\n", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if oldSize <= newCp.Size {
			log.Printf("old size must be less than or equal to the new size\n")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if oldSize != treeSize {
			log.Printf("old size and last verified size must match\n")
			w.WriteHeader(http.StatusConflict)
			w.Header().Add("Content-Type", "text/x.tlog.size")
			_, _ = w.Write([]byte(fmt.Sprintf("%d\n", treeSize)))
			return
		}

		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, oldSize, newCp.Size, consistencyProof, treeHash, newCp.Hash); err != nil {
			log.Printf("proof did not verify: %v\n", err)
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		cosignedCheckpoint, err := tlog_note.Sign(newCpNote, witnessSigner)
		if err != nil {
			log.Printf("error cosigning checkpoint: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if r, err := db.Exec("UPDATE tlog SET tree_size = ?, tree_hash = ? WHERE origin = ? AND tree_size = ?",
			newCp.Size, base64.RawStdEncoding.EncodeToString(newCp.Hash), origin, oldSize); err != nil {
			log.Printf("error updating stored checkpoint: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if c, err := r.RowsAffected(); err != nil {
			log.Printf("error reading rows after storing checkpoint: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if c != 1 {
			rows, err := db.Query("SELECT tree_size FROM tlog WHERE origin = ?", origin)
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

			w.WriteHeader(http.StatusConflict)
			w.Header().Add("Content-Type", "text/x.tlog.size")
			_, _ = w.Write([]byte(fmt.Sprintf("%d\n", treeSize)))
			return
		}

		_, sig, ok := bytes.Cut(cosignedCheckpoint, []byte("\n\n"))
		if !ok {
			log.Printf("error splitting cosigned checkpoint\n")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if _, err = w.Write(sig); err != nil {
			log.Printf("/add-checkpoint: %v", err)
			return
		}
	})

	address := fmt.Sprintf("%s:%d", *host, *port)
	if err := http.ListenAndServe(address, http.DefaultServeMux); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
