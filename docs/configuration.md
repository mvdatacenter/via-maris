# Configuring and pointing clients at via-maris

`via-maris` is a single Go program built from the standard library alone. The gateway reads one JSON file, named as its only argument. [`config.example.json`](../config.example.json) carries every field. A configuration with an unknown field or one that fails validation stops the gateway at startup. `via-maris recheck <recheck.json>` runs the re-check instead, as [The re-check](#the-re-check) describes.

```
go test ./...
docker build -t via-maris .
docker run -p 8480:8480 -v "$PWD/config.json:/etc/via-maris/config.json:ro" via-maris
```

Each `v*` tag publishes `ghcr.io/mvdatacenter/via-maris:<tag>`, built with the tag as the version that `/healthz` and `/metrics` report and signed by this repository's release workflow with cosign keyless signing. The package is private, so pulling the image or checking its signature needs a login with a GitHub token that has the `read:packages` scope. This logs in and checks the signature:

```
echo "$TOKEN" | docker login ghcr.io -u <github-user> --password-stdin
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
- `byName` (optional): serves one PyPI upstream under the host names of its `url` and `files`, as [PyPI by its own names](#pypi-by-its-own-names) describes. `listen` is the TLS listener's address, `upstream` names the PyPI upstream, and `cert`, `key` and `ca` are the files holding the leaf certificate, its key and the CA certificate that signed it.

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

## PyPI by its own names

A uv lockfile records the index it was resolved at and each file's URL, so a lock resolved at `pypi.org` names `pypi.org` and `files.pythonhosted.org` whatever index the machine installing it is set to. `byName` lets those installs reach the check with the lock unchanged. The gateway answers TLS for the two host names of the upstream's `url` and `files` and serves them as the upstream does:

- `/simple/<project>/` on the index host is the simple index, with refused files yanked with their reason and every file URL left on the files host.
- `/pypi/<project>/json` and `/pypi/<project>/<version>/json` on the index host are the JSON API, with each refused file's `yanked` set and its `yanked_reason` naming why.
- Every path on the files host is checked as the `/<name>/files/` path is: the package and version are read from the wheel or sdist file name and the file is served only when the project's index lists it.

A client reaches it in either of two ways:

- **By resolving the names to the gateway.** A host entry, or a pod's `hostAliases`, maps both names to the address that serves `byName.listen` on port 443.
- **Through `CONNECT`.** With the main listener as its HTTPS proxy, a client asks for `CONNECT pypi.org:443` or `CONNECT files.pythonhosted.org:443`, and the tunnel is answered by the same TLS server. A `CONNECT` to any other host or port is refused with 403 and recorded.

| Client | Setting |
| --- | --- |
| uv | `HTTPS_PROXY=http://via-maris:8480`, `SSL_CERT_FILE=<bundle with the CA>` and `UV_SYSTEM_CERTS=1` |
| pip | `proxy = http://via-maris:8480` and `cert = <bundle with the CA>` in `pip.conf`, with no index |

Every client that installs through `byName` trusts the CA in `ca`, so that CA should carry name constraints permitting the two host names alone. The gateway reads the leaf, key and CA from files and checks them on each handshake, so a certificate manager that replaces them on renewal needs no restart. A pair that fails to load leaves the previous one in use. Until a pair has loaded, `/healthz` reports the TLS certificate as not ready and the listener refuses handshakes. The listener speaks HTTP/1.1 alone, so a refusal reaches pip in the status line.

## Operating

- `GET /healthz` answers 503 and names what is not ready: an ecosystem's advisory data, a Go index, the record upload, or with `byName` the TLS certificate. A stale in-use set only stops fix releases from passing the hold, so the gateway stays ready.
- `GET /metrics` serves Prometheus text. With `byName`, `via_maris_tls_expiry_timestamp_seconds` gives the leaf's and the CA's expiry as Unix time, labelled `certificate="leaf"` and `certificate="ca"`, and 0 before a pair has loaded.

A refused version is answered 403, with the refusal reason in the response.

## The re-check

`via-maris recheck <recheck.json>` makes one pass and exits, so a scheduler runs it on an interval. [`recheck.example.json`](../recheck.example.json) carries every field. A pass:

1. Loads the OSV exports for each of `ecosystems` from `advisories.source`, the same exports the gateway reads.
2. Mints an installation token for the GitHub App that `github` names, asking for Contents read alone. The App's id, installation id and PEM private key are read from the environment variables the section names.
3. Downloads the default branch of every repository the installation reaches under `github.owner`, leaving out archived ones, into a directory of its own under `workDir`, which it removes when it ends. Only regular files and directories are written.
4. Runs the OSV-Scanner binary at `osvScanner` over them to list every locked package version. OSV-Scanner's own vulnerability matching is switched off. The versions are matched against the exports by the gateway's own check, so a lockfile entry is judged exactly as an install of it would be.
5. Posts one `LockedVersionListedMalicious` alert per repository, lockfile, package, version and advisory to `alertmanager`, at severity `critical`. Each alert ends `alertFor` after the pass, so it stays firing while every pass finds the version and resolves once passes stop finding it. `alertFor` should exceed the interval between passes.
6. Writes the in-use set to `inUse`: every locked version, and every version the gateway served within `servedWindow`, read from the decision records under `records`. Only records uploaded since the last pass are read, starting `records.overlap` earlier to catch a slow upload. When the previous set is missing or cannot be parsed, the whole window is read again; when the store cannot be reached, the pass fails. The set is stamped with the time the pass started. Just before the write the pass reads the set's ETag again, and the write itself is conditional on that ETag, so when two passes overlap, the one that read an older set fails rather than replacing a newer one. Garage v2.4.1 does not apply those conditions: run against it, a PUT with a stale `If-Match` and a second PUT with `If-None-Match: *` both replaced the object. There a write landing between the re-read and the pass's own write still wins. What it replaced is back after the next pass, because each set holds everything up to the records position it names and the next pass reads the records again from there. A scheduler runs one pass at a time, so the set does not step back in between.

Any failure exits non-zero and leaves the previous set in place, where the gateway's `inUse.maxAge` reads its age. The image carries OSV-Scanner at `/osv-scanner`. Neither binary has a writable directory of its own, so `workDir` must be a mounted writable volume.
