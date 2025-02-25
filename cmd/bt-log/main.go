package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/haydentherapper/bt-log/pkg/note"
	"github.com/haydentherapper/bt-log/pkg/purl"
	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/client"
	"github.com/transparency-dev/trillian-tessera/storage/posix"
)

var (
	host        = flag.String("host", "localhost", "host to listen on")
	port        = flag.Uint("port", 8080, "port to listen on")
	storageDir  = flag.String("storage-dir", "", "Root directory to store log data")
	purlType    = flag.String("purl-type", "", "Restricts pURLs to be of a specific type")
	privKeyFile = flag.String("private-key", "", "Location of private key file. If unset, uses the contents of the LOG_PRIVATE_KEY environment variable.")
	pubKeyFile  = flag.String("public-key", "", "Location of public key file. If unset, uses the contents of the LOG_PUBLIC_KEY environment variable.")
)

func addCacheHeaders(value string, fs http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", value)
		fs.ServeHTTP(w, r)
	}
}

type LogEntry struct {
	PURL string `json:"purl"` // e.g. pkg:pypi/pkgname@1.2.3?digest=0102030405
}

type LogEntryResponse struct {
	Index          uint64   `json:"index"`
	Checkpoint     []byte   `json:"checkpoint"`
	InclusionProof [][]byte `json:"inclusionProof"`
}

func main() {
	flag.Parse()

	if *storageDir == "" {
		log.Fatalf("--storage-dir must be set")
	}
	if *purlType == "" {
		log.Fatalf("--purl-type must be set")
	}

	ctx := context.Background()

	// Create NoteSigner/Verifier for signing/verifying checkpoints
	s, err := note.GetNoteSigner(*privKeyFile, "LOG_PRIVATE_KEY")
	if err != nil {
		log.Fatal(err)
	}
	v, err := note.GetNoteVerifier(*pubKeyFile, "LOG_PUBLIC_KEY")
	if err != nil {
		log.Fatal(err)
	}

	// Create the Tessera POSIX storage, using the directory from the --storage-dir flag
	driver, err := posix.New(ctx, *storageDir)
	if err != nil {
		log.Fatalf("failed to construct driver: %v", err)
	}
	appender, r, err := tessera.NewAppender(ctx,
		driver,
		tessera.WithCheckpointSigner(s),
		tessera.WithCheckpointInterval(5*time.Second),
		tessera.WithBatching(256, time.Second),
		tessera.WithAppendDeduplication(tessera.InMemoryDedupe(256)))
	if err != nil {
		log.Fatalf("failed to create appender: %v", err)
	}
	addFn := appender.Add
	tileFetcher := r.ReadTile
	await := tessera.NewIntegrationAwaiter(ctx, r.ReadCheckpoint, time.Second)

	// Define a handler for /add that accepts POST requests and adds the POST body to the log
	http.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Parse request
		var e LogEntry
		if err := json.Unmarshal(b, &e); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		if err := purl.VerifyPURL(e.PURL, *purlType); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		f := addFn(r.Context(), tessera.NewEntry([]byte(e.PURL)))
		idx, rawCp, err := await.Await(ctx, f)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		cp, _, _, err := tlog.ParseCheckpoint(rawCp, v.Name(), v)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		pb, err := client.NewProofBuilder(ctx, *cp, tileFetcher)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		inclusionProof, err := pb.InclusionProof(ctx, idx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		// make sure the proof is valid
		leafHash := rfc6962.DefaultHasher.HashLeaf([]byte(e.PURL))
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, cp.Size, leafHash, inclusionProof, cp.Hash); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		resp := LogEntryResponse{
			Index:          idx,
			Checkpoint:     rawCp,
			InclusionProof: inclusionProof,
		}
		jResp, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		if _, err = w.Write(jResp); err != nil {
			log.Printf("/add: %v", err)
			return
		}
	})

	// Proxy all GET requests to the filesystem as a lightweight file server.
	// This makes it easier to test this implementation from another machine.
	fs := http.FileServer(http.Dir(*storageDir))
	http.Handle("GET /checkpoint", addCacheHeaders("no-cache", fs))
	http.Handle("GET /tile/", addCacheHeaders("max-age=31536000, immutable", fs))

	address := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Printf("Environment variables useful for accessing this log:\n"+
		"export WRITE_URL=http://localhost%s/ \n"+
		"export READ_URL=http://localhost%s/ \n", address, address)

	if err := http.ListenAndServe(address, http.DefaultServeMux); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
