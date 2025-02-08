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
go run ./cmd/bt-log --storage-dir=/tmp/mylog --private-key=private.key --public-key=public.key --purl-type=pypi --initialize
```

Replace `--purl-type` with the name of the package registry.

For future runs, **you must remove `--initialize`**. Otherwise, the log
will become corrupted.
