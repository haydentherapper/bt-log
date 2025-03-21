package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"github.com/transparency-dev/trillian-tessera/client"
	"golang.org/x/mod/sumdb/note"
)

var (
	logURL     = flag.String("log-url", "", "Log URL")
	pubKeyPath = flag.String("public-key", "", "Path for log public key")
	storageDir = flag.String("storage-dir", "", "Directory to store last verified checkpoint")
	once       = flag.Bool("once", true, "Whether to run in a loop or not")
	frequency  = flag.Duration("frequency", time.Minute, "How often to run the monitor")
)

// TODO: Add pURL regex matcher
// TODO: Verify entries's ID->hash mapping is unique
// TODO: Request entry from registry, compare hash
func main() {
	flag.Parse()

	if *logURL == "" {
		log.Fatal("--log-url must be set")
	}
	if *pubKeyPath == "" {
		log.Fatal("--public-key must be set")
	}
	if *storageDir == "" {
		log.Fatal("--storage-dir must be set")
	}

	ticker := time.NewTicker(*frequency)
	defer ticker.Stop()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// for-select at end of loop due to ticker not ticking initially
	for {
		lURL, err := url.Parse(*logURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing log URL: %v", err)
			return
		}

		// Initialize client to fetch latest checkpoint and entry bundles
		logFetcher, err := client.NewHTTPFetcher(lURL, http.DefaultClient)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating log HTTP client: %v", err)
			return
		}

		// Create checkpoint verifier using log public key
		pubKey, err := os.ReadFile(*pubKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read public key file %s: %v", *pubKeyPath, err)
			return
		}
		v, err := note.NewVerifier(string(pubKey))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize checkpoint verifier for %s: %v", *pubKeyPath, err)
			return
		}

		// Parse and verify previous and latest checkpoints
		checkpointPath := path.Join(*storageDir, "checkpoint")
		previousCPBytes, err := os.ReadFile(checkpointPath)
		first := false
		if err != nil {
			// Handle when no checkpoint exists, for the first run of the monitor
			if errors.Is(err, os.ErrNotExist) {
				first = true
			} else {
				fmt.Fprintf(os.Stderr, "failed to read previous checkpoint: %v", err)
				return
			}
		}
		var previousCP *tlog.Checkpoint
		if first {
			emptyRoot := sha256.Sum256([]byte{})
			previousCP = &tlog.Checkpoint{
				Origin: v.Name(),
				Size:   0,
				Hash:   emptyRoot[:],
			}
		} else {
			previousCP, _, _, err = tlog.ParseCheckpoint(previousCPBytes, v.Name(), v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to verify previous checkpoint: %v", err)
				return
			}
		}
		latestCPBytes, err := logFetcher.ReadCheckpoint(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading latest log checkpoint: %v", err)
			return
		}
		latestCP, _, _, err := tlog.ParseCheckpoint(latestCPBytes, v.Name(), v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to verify latest checkpoint: %v", err)
			return
		}

		// Pass the latest checkpoint even though we haven't verified consistency yet.
		// It's only used for building inclusion proofs, which aren't needed here.
		pb, err := client.NewProofBuilder(context.Background(), *latestCP, logFetcher.ReadTile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating proof builder: %v", err)
			return
		}

		// Verify consistency before requesting new entries
		consistencyProof, err := pb.ConsistencyProof(context.Background(), previousCP.Size, latestCP.Size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error constructing consistency proof: %v", err)
			return
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, previousCP.Size, latestCP.Size, consistencyProof, previousCP.Hash, latestCP.Hash); err != nil {
			fmt.Fprintf(os.Stderr, "error verifying consistency proof: %v", err)
			return
		}

		// Iterate over all entry bundles, from the previous up to latest log size
		entryBundles := layout.Range(previousCP.Size, latestCP.Size-previousCP.Size, latestCP.Size)
		for eb := range entryBundles {
			entries, err := client.GetEntryBundle(context.Background(), logFetcher.ReadEntryBundle, eb.Index, latestCP.Size)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error fetching entry bundle for tile index %d, log size %d", eb.Index, latestCP.Size)
				return
			}
			// Iterate over each entry in the bundle, which may be from a partial tile
			for _, e := range entries.Entries[eb.First:] {
				// TODO: Alert when there's a match
				pURL := string(e)
				fmt.Println(pURL)
			}
		}

		// Persist latest checkpoint
		if err := os.MkdirAll(*storageDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating directory for checkpoint: %v", err)
			return
		}
		if err := os.WriteFile(checkpointPath, latestCPBytes, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing latest checkpoint: %v", err)
			return
		}

		// Exit early if continuous monitoring isn't requested
		if *once {
			return
		}

		// Wait until a tick or SIGTERM
		select {
		case <-ticker.C:
			continue
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "received signal, exiting")
			return
		}
	}
}
