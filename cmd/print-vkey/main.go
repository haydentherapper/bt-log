package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/haydentherapper/bt-log/internal/key"
	"golang.org/x/mod/sumdb/note"
)

var (
	origin     = flag.String("origin", "", "Origin of witness, e.g. example.com/witness")
	pubKeyPath = flag.String("public-key-path", "", "path to PEM or Base64-encoded DER ED25519 public key")
)

func main() {
	flag.Parse()
	if *origin == "" {
		log.Fatalf("--origin must be set")
	}
	if *pubKeyPath == "" {
		log.Fatalf("--public-key-path must be set")
	}
	pubKey, err := os.ReadFile(*pubKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	ed25519Key, err := key.ParseEd25519PublicKey(string(pubKey))
	if err != nil {
		log.Fatal(err)
	}
	vkey, err := note.NewEd25519VerifierKey(*origin, ed25519Key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(vkey)
}
