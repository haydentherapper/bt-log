package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/mod/sumdb/note"

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
	initialize  = flag.Bool("initialize", false, "Set when creating a new log to initialize the structure")
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

	// Gather the info needed for reading/writing checkpoints
	s := getSignerOrDie()
	v := getVerifierOrDie()

	// Create the Tessera POSIX storage, using the directory from the --storage-dir flag
	driver, err := posix.New(ctx,
		*storageDir,
		*initialize,
		tessera.WithCheckpointSigner(s),
		tessera.WithCheckpointInterval(time.Second),
		tessera.WithBatching(256, time.Second))
	if err != nil {
		log.Fatalf("failed to construct storage: %v", err)
	}

	// Create function to handle adding entries
	addFn, r, err := tessera.NewAppender(driver, tessera.InMemoryDedupe(256))
	if err != nil {
		log.Fatalf("failed to create appender: %v", err)
	}
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

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *host, *port), http.DefaultServeMux); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

// Read log private key from file or environment variable
func getSignerOrDie() note.Signer {
	var privKey string
	var err error
	if len(*privKeyFile) > 0 {
		privKey, err = getKeyFile(*privKeyFile)
		if err != nil {
			log.Fatalf("unable to read private key: %v", err)
		}
	} else {
		privKey = os.Getenv("LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			log.Fatalf("provide private key file path using --private-key or set LOG_PRIVATE_KEY env var")
		}
	}
	s, err := note.NewSigner(privKey)
	if err != nil {
		log.Fatalf("failed to initialize signer: %v", err)
	}
	return s
}

// Read log public key from file or environment variable
func getVerifierOrDie() note.Verifier {
	var pubKey string
	var err error
	if len(*pubKeyFile) > 0 {
		pubKey, err = getKeyFile(*pubKeyFile)
		if err != nil {
			log.Fatalf("unable to read public key: %v", err)
		}
	} else {
		pubKey = os.Getenv("LOG_PUBLIC_KEY")
		if len(pubKey) == 0 {
			log.Fatalf("provide public key file path using --public-key or set LOG_PUBLIC_KEY env var")
		}
	}
	v, err := note.NewVerifier(pubKey)
	if err != nil {
		log.Fatalf("failed to initialize verifier: %v", err)
	}
	return v
}

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}
