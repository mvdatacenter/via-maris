# Configuring and pointing clients at via-maris

`via-maris` is a single Go program built from the standard library alone. The gateway reads one JSON file, named as its only argument. [`config.example.json`](../config.example.json) carries every field. A configuration with an unknown field or one that fails validation stops the gateway at startup. `via-maris recheck <recheck.json>` runs the re-check instead, as [The re-check](#the-re-check) describes.

```
go test ./...
docker build -t via-maris .
docker run -p 8480:8480 -v "$PWD/config.json:/etc/via-maris/config.json:ro" via-maris
```

Each `v*` tag publishes `ghcr.io/mvdatacenter/via-maris:<tag>`, built with the tag as the version that `/healthz` and `/metrics` report and signed by this repository's release workflow with cosign keyless signing. This checks the signature:

```
cosign verify ghcr.io/mvdatacenter/via-maris:<tag> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/mvdatacenter/via-maris/\.github/workflows/release\.yml@refs/tags/v'
```

## Sections

- `listen`: the address to serve on, `:8480` in the example.
- `advisories`: where the OSV per-ecosystem `all.zip` exports are read from. `refresh` sets how often they are re-read. `maxAge` sets how old the loaded data may be before every checked request is refused.
- `inUse`: an object in an S3-compatible store that lists the versions already in use, shaped `{"generated": "<RFC 3339>", "ecosystems": {"npm": {"<package>": ["<version>"]}}}`. The re-check writes it. A version inside the hold is served when it fixes an advisory against a version in that list. `maxAge` bounds how stale the object may be.
- `records`: where decision records are uploaded, as NDJSON batches under `prefix`. A record is written to stdout for every decision. Once the oldest unshipped record is older than `maxUnshipped`, every request is answered 503.
- `upstreams`: one entry per registry fronted, served under `/<name>/`.

The access keys for both stores are read from the environment variables the store names. A store's endpoint is given either as `endpoint` or, when it carries a value kept out of the configuration such as an account id, as `endpointEnv`, the environment variable that holds it.

## Upstream policy

- `hold`: the release-age hold. A version published more recently than this is refused.
- `advisories`: `malicious` refuses versions that a `MAL-` advisory lists. `all` refuses a version that any advisory lists.
- `exceptions`: admit one version through the hold. Each exception names the package, version, a reason, the review that approved it, and an `expires` date. It applies only until that date, and to the hold alone: the advisory check still refuses a malicious version.

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

- `GET /healthz` answers 503 and names what is not ready: an ecosystem's advisory data, a Go index, or the record upload. A stale in-use set only stops fix releases from passing the hold, so the gateway stays ready.
- `GET /metrics` serves Prometheus text.

A refused version is answered 403, with the refusal reason in the response.

## The re-check

`via-maris recheck <recheck.json>` makes one pass and exits, so a scheduler runs it on an interval. [`recheck.example.json`](../recheck.example.json) carries every field. A pass:

1. Loads the OSV exports for each of `ecosystems` from `advisories.source`, the same exports the gateway reads.
2. Mints an installation token for the GitHub App that `github` names, asking for Contents read alone. The App's id, installation id and PEM private key are read from the environment variables the section names.
3. Downloads the default branch of every repository the installation reaches under `github.owner`, leaving out archived ones, into a directory of its own under `workDir`, which it removes when it ends. Only regular files and directories are written.
4. Runs the OSV-Scanner binary at `osvScanner` over them to list every locked package version. OSV-Scanner's own vulnerability matching is switched off. The versions are matched against the exports by the gateway's own check, so a lockfile entry is judged exactly as an install of it would be.
5. Posts one `LockedVersionListedMalicious` alert per repository, lockfile, package, version and advisory to `alertmanager`, at severity `critical`. Each alert ends `alertFor` after the pass, so it stays firing while every pass finds the version and resolves once passes stop finding it. `alertFor` should exceed the interval between passes.
6. Writes the in-use set to `inUse`: every locked version, and every version the gateway served within `servedWindow`, read from the decision records under `records`. Only records uploaded since the last pass are read, starting `records.overlap` earlier to catch a slow upload. When the previous set is missing or cannot be parsed, the whole window is read again; when the store cannot be reached, the pass fails. The set is stamped with the time the pass started. Just before the write the pass reads the set's ETag again, and the write itself is conditional on that ETag, so when two passes overlap, the one that read an older set fails rather than replacing a newer one. Garage v2.4.1 ignores conditional writes, so there only the re-read guards the set, and a write landing between it and the pass's own write still wins: a scheduler runs one pass at a time.

Any failure exits non-zero and leaves the previous set in place, where the gateway's `inUse.maxAge` reads its age. The image carries OSV-Scanner at `/osv-scanner`. Neither binary has a writable directory of its own, so `workDir` must be a mounted writable volume.
