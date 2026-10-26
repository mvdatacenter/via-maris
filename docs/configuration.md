# Configuring and pointing clients at via-maris

`via-maris` is a single Go program built from the standard library alone. The gateway reads one JSON file, named as its only argument. [`config.example.json`](../config.example.json) carries every field. A configuration with an unknown field or one that fails validation stops the gateway at startup. `via-maris recheck` is the same program's re-check, configured as [The re-check](#the-re-check) describes.

```
go test ./...
docker build -t via-maris .
docker run -p 8480:8480 -v "$PWD/config.json:/etc/via-maris/config.json:ro" via-maris
```

Each `v*` tag publishes the gateway as `ghcr.io/mvdatacenter/via-maris:<tag>`, built with the tag as the version that `/healthz` and `/metrics` report, and the re-check as `ghcr.io/mvdatacenter/via-maris:<tag>-recheck`. This repository's release workflow signs both with cosign keyless signing. This checks the gateway's signature, and the same command naming `:<tag>-recheck` checks the re-check's:

```
cosign verify ghcr.io/mvdatacenter/via-maris:<tag> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/mvdatacenter/via-maris/\.github/workflows/release\.yml@refs/tags/v'
```

## Sections

- `listen`: the address to serve on, `:8480` in the example.
- `advisories`: where the OSV per-ecosystem `all.zip` exports are read from. `refresh` sets how often they are re-read. `maxAge` sets how old the loaded data may be before every checked request is refused.
- `inUse`: an object in an S3-compatible store that lists the versions already in use, shaped `{"generated": "<RFC 3339>", "ecosystems": {"npm": {"<package>": ["<version>"]}}}`. A version inside the hold is served when it fixes an advisory against a version in that list. `maxAge` bounds how stale the object may be. `via-maris recheck` writes the object.
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

The gateway checks each request against the current advisories, so a version listed as malicious after it was served is refused on its next install. A version already locked in a repository is found by `via-maris recheck <recheck.json>` instead, run on a schedule. [`recheck.example.json`](../recheck.example.json) carries every field.

```
docker build -t via-maris-recheck --target recheck .
docker run -v "$PWD/recheck.json:/etc/via-maris/recheck.json:ro" via-maris-recheck
```

Each run does the following:

1. It mints an installation token for a GitHub App, asking for Contents read alone, and reads the default branch of every non-archived repository of `github.org` that the installation reaches. It downloads each branch as a tarball and writes only the regular files.
2. It runs [OSV-Scanner](https://github.com/google/osv-scanner) over every lockfile with OSV's offline databases. The image carries OSV-Scanner at a pinned release.
3. It writes the in-use set to `inUse`. The set holds every npm, PyPI and Go version a lockfile pins, and every version the gateway's decision records under `records` show it served inside `window`. It is stamped with the run's start time. The object also keeps the time of the newest record object read and each served version's last-served time, so the next run reads only newer records. If the object is lost, the next run rebuilds it from the whole window.
4. It posts one `LockedVersionListedMalicious` alert per repository, lockfile, package and version that a `MAL-` advisory lists to the Alertmanager at `alertmanager.url`. Each run posts the alert again, so an alert resolves `resolveAfter` past the last run that found the version.

A run that cannot fetch a repository, scan, or read the stores fails without writing the set, so the set's age shows the failure. A run whose alert post fails exits non-zero after writing the set. The App's id, installation id and PEM private key are read from the environment variables that `github` names. `scanner.workDir` must be writable and hold every repository's files.
