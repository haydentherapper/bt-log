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

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func main() {
	flag.Parse()
	if *origin == "" {
		log.Fatalf("--origin must be set")
	}
	if fileExists(*privKeyPath) {
		log.Fatalf("--private-key-path file must not exist")
	}
	if fileExists(*pubKeyPath) {
		log.Fatalf("--public-key-path file must not exist")
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
