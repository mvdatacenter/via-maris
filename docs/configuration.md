# Configuring and pointing clients at via-maris

`via-maris` is a single Go program built from the standard library alone. It reads one JSON file, named as its only argument. [`config.example.json`](../config.example.json) carries every field. Unknown fields are rejected, and so is a configuration that fails validation; the gateway then does not start.

```
go test ./...
docker build -t via-maris .
docker run -p 8480:8480 -v "$PWD/config.json:/etc/via-maris/config.json:ro" via-maris
```

## Sections

- `listen`: the address to serve on, `:8480` in the image.
- `advisories`: where the OSV per-ecosystem `all.zip` exports are read from. `refresh` sets how often they are re-read. `maxAge` sets how old the loaded data may be before every checked request is refused.
- `inUse`: an object in an S3-compatible store that lists the versions already in use, shaped `{"generated": "<RFC 3339>", "ecosystems": {"npm": {"<package>": ["<version>"]}}}`. A version inside the hold is served when it fixes an advisory against a version in that list. `maxAge` bounds how stale the object may be.
- `records`: where decision records are uploaded, as NDJSON batches under `prefix`. A record is written to stdout for every decision. Once the oldest unshipped record is older than `maxUnshipped`, every request is answered 503.
- `upstreams`: one entry per registry fronted, served under `/<name>/`.

The access keys for both stores are read from the environment variables the store names.

## Upstream policy

- `hold`: the release-age hold. A version published more recently than this is refused.
- `advisories`: `malicious` refuses versions that a `MAL-` advisory lists. `all` refuses a version that any advisory lists.
- `exceptions`: admit one version through the hold. Each exception names the package, version, a reason, the review that approved it, and an `expires` date. It applies only until that date. No exception admits a malicious version.

## Clients

With the gateway at `http://via-maris:8480` and the upstream names from the example:

| Client | Setting |
| --- | --- |
| npm | `registry=http://via-maris:8480/npm/` |
| pip, uv | `index-url = http://via-maris:8480/pypi/simple/` |
| go | `GOPROXY=http://via-maris:8480/go` (the go command reaches the checksum database through the same proxy) |
| apt | `deb http://via-maris:8480/apt/ubuntu <suite> main` |
| files | `http://via-maris:8480/files/<pinned name>` |

The checks differ by front end:

- **npm, PyPI and Go** are checked one version at a time.
- **apt** is served from a dated archive snapshot taken one hold back.
- **files** serves only names that are pinned to a SHA-256 digest.

## Operating

- `GET /healthz` answers 503 and names what is not ready (for example advisory data, the in-use set, the Go index, or the record upload).
- `GET /metrics` serves Prometheus text.

A refused version is answered 403. The reason names the package, the version, and the advisory or the age that refused it.
