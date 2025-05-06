# Binary Transparency for Package Registries

This repo contains an implementation of a transparency log for binary transparency
for package registries.

`cmd/bt-log` provides an HTTP server that accepts POST requests to an `/add` endpoint.
The JSON request should contain a single string, a package identified by a
[pURL](https://github.com/package-url/purl-spec/) string:

```json
{
    "purl": "pkg:pypi/my-package@1.2.3?digest=sha256:3b9730808f265c6d174662668435c4cf1fc9ddcd369831a646fa84bff8594f0c"
}
```

The pURL must contain:

1. A pURL type that matches the name of the package registry, e.g. `pypi`, `gem`
2. The name of a package. Namespace is optional
3. The package version, e.g. `1.2.3`, `v1.2.3`
4. A single qualifier containing the SHA 256 digest

The JSON response will include the index of the entry, the inclusion proof, and the checkpoint
as per the [C2SP checkpoint spec](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md):

```json
{
    "index": 123,
    "checkpoint": "base64(checkpoint)",
    "inclusionProof": ["base64(hash)", "base64(hash)"]
}
```

The HTTP server also exposes endpoints per the [C2SP tlog-tiles spec](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md):

* `/checkpoint`, which is updated every second
* `/tile`, which serves the raw tile data and entry bundles

## Log deployment

This will create a directory in the filesystem to store a log, and start the HTTP server
that can add entries to this log.

First, generate private and public keys:

```shell
go run ./cmd/gen-key --origin=binarytransparency.log/example
```

This will output private and public keys in Go's signed note format:

```
cat private.key
PRIVATE+KEY+binarytransparency.log/example+5de0f997+AXNNv9racVtMynH7oHIogZ4xS5sAIHBl47hlrcf6vsfu

cat public.key
binarytransparency.log/example+5de0f997+AcPfp2roeTxqSqmPdDkA9rIAd0pe3C5Je6Rze2SqBDUp
```

Then, start the log:

```shell
go run ./cmd/bt-log --storage-dir=/tmp/bt-log --private-key=private.key --public-key=public.key --purl-type=pypi
```

Replace `--purl-type` with the name of the package registry.

### Witnessing

To prevent split-view attacks, where a log serves different views to different callers,
checkpoints must be witnessed, where an independent auditor verifies a consistency proof
that the log remains append-only and returns a cosignature over the checkpoint.

This repository contains a lightweight witness that implements the
[C2SP tlog-witness spec](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md).

To initialize the witness, create a SQLite database and a signing key. The database will store
a log's verification key and origin, and the last size and tree hash the witness verified. 

The commands below will initialize the log signing key, create the database, initialize the database, add a row with the
log's verification key, generate a witness signing key, and start the witness.

```
go run ./cmd/gen-key --origin=binarytransparency.log/example

sqlite3 -line witness.db '.database'
go run ./cmd/witness-add-key --database-path witness.db --public-key public.key

go run ./cmd/gen-key --origin=witness.log/example --private-key-path witness-private.key --public-key-path witness-public.key
go run ./cmd/witness-server --database-path witness.db --private-key witness-private.key --public-key witness-public.key
```

Then, start the log. The log will verify cosigned checkpoints using the provided witness verification key.

```
go run ./cmd/bt-log --storage-dir=/tmp/bt-log --private-key=private.key --public-key=public.key --purl-type=pypi --witness-url="http://localhost:8081" --witness-public-key=witness-public.key
```

The checkpoint in the log's response will contain a co-signed checkpoint:

```
curl -XPOST http://localhost:8080/add -d "{\"purl\":\"pkg:pypi/pkgname@1.2.3?digest=sha256:5141b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be92\"}" -o bundle

cat bundle | jq -r .checkpoint | base64 -d
```

The signed checkpoint will have two signatures, one from the log and one from the witness.

# Docker Deployment

Using the provided Docker Compose file, you can initialize and deploy the log and witness.

Run the following administrative jobs once to generate the log and witness keys and initialize the witness database:

```
docker compose --profile admin build
docker compose run gen-key-log
docker compose run gen-key-witness
docker compose run init-witness
```

Run the log and witness:

```
docker compose up --wait
```

To clean up containers and volumes:

```
docker-compose down --remove-orphans --volumes
```

# Upcoming Work

- [ ] Change pURL to a custom representation
- [ ] Lightweight monitor to demonstrate verifying ID-hash mapping is always 1-1 and alerting on publication
  - [x] ID-hash mapping verification
  - [x] Regex to match entries
  - [x] Use slog for output
  - [ ] Transform pURL to entry, request entry from registry, compare hash
  - [x] Add e2e to GHA script
- [ ] Add unit tests
- [x] Containerize for e2e tests
