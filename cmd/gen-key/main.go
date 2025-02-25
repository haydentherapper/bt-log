package main

import (
	"crypto/rand"
	"flag"
	"log"
	"os"

	"golang.org/x/mod/sumdb/note"
)

var (
	origin      = flag.String("origin", "", "Origin of checkpoint, e.g. example.com/log")
	privKeyPath = flag.String("private-key-path", "private.key", "Output path for private key")
	pubKeyPath  = flag.String("public-key-path", "public.key", "Output path for public key")
)

func main() {
	flag.Parse()
	if *origin == "" {
		log.Fatalf("--origin must be set")
	}

	privKey, pubKey, err := note.GenerateKey(rand.Reader, *origin)
	if err != nil {
		log.Fatalf("error generating key: %v", err)
	}

	if err := os.WriteFile(*privKeyPath, []byte(privKey), 0o644); err != nil {
		log.Fatalf("error writing private key: %v", err)
	}
	if err := os.WriteFile(*pubKeyPath, []byte(pubKey), 0o644); err != nil {
		log.Fatalf("error writing public key: %v", err)
	}
}
