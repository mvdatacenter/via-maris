# Configuring and pointing clients at via-maris

`via-maris` is a single Go program built from the standard library alone. The gateway reads one JSON file, named as its only argument. [`config.example.json`](../config.example.json) carries every field. A configuration with an unknown field or one that fails validation stops the gateway at startup. `via-maris recheck <recheck.json>` runs the re-check instead, as [The re-check](#the-re-check) describes, `via-maris egress-observe <egress-observe.json>` the egress observer, as [The egress observer](#the-egress-observer) describes, and `via-maris hold-lag <hold-lag.json> [YYYY-MM]` the monthly report, as [The hold-lag report](#the-hold-lag-report) describes.

```
go test ./...
docker build -t via-maris .
docker run -p 8480:8480 -v "$PWD/config.json:/etc/via-maris/config.json:ro" via-maris
```

Each `v*` tag publishes `ghcr.io/mvdatacenter/via-maris:<tag>`, built with the tag as the version that `/healthz` and `/metrics` report and signed by this repository's release workflow with cosign keyless signing. The package is public, so pulling the image or checking its signature needs no login. This checks the signature:

```
cosign verify ghcr.io/mvdatacenter/via-maris:<tag> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/mvdatacenter/via-maris/\.github/workflows/release\.yml@refs/tags/v'
```

## Sections

- `listen`: the address to serve on, `:8480` in the example.
- `advisories`: where the OSV per-ecosystem `all.zip` exports are read from. `refresh` sets how often they are re-read. `maxAge` sets how old the loaded data may be before every checked request is refused.
- `inUse`: an object in an S3-compatible store that lists the versions already in use, shaped `{"generated": "<RFC 3339>", "ecosystems": {"npm": {"<package>": ["<version>"]}}}`. The re-check writes it. A version inside the hold is served when it fixes an advisory against a version in that list. `maxAge` bounds how stale the object may be.
- `records`: where decision records are uploaded, as NDJSON batches under `prefix`. A record is written to stdout for every decision. A record of a version whose publication time the check read carries that time as `published`, so it stays known after the upstream removes the version. For a Go module that time is when the module proxy first served the version, which the gateway reads from the Go index for the last hold and an hour, so a Go version first served before then carries none. Once the oldest unshipped record is older than `maxUnshipped`, every request is answered 503.
- `upstreams`: one entry per registry fronted, served under `/<name>/`.
- `byName` (optional): serves one PyPI upstream under the host names of its `url` and `files`, as [PyPI by its own names](#pypi-by-its-own-names) describes. `listen` is the TLS listener's address, `upstream` names the PyPI upstream, and `cert`, `key` and `ca` are the files holding the leaf certificate, its key and the CA certificate that signed it. `npm` (optional) serves one npm upstream on the same listener, as [npm by its own names](#npm-by-its-own-names) describes: `upstream` names it, `hosts` lists the names it answers, and `cert`, `key` and `ca` are its own. `maven` (optional) serves Maven upstreams, SDK listings and held pinned files on the same listener, as [Maven and pinned files by their own names](#maven-and-pinned-files-by-their-own-names) describes.

The access keys for both stores are read from the environment variables the store names. A store's endpoint is given either as `endpoint` or, when it carries a value kept out of the configuration such as an account id, as `endpointEnv`, the environment variable that holds it.

## Upstream policy

- `hold`: the release-age hold. A version published more recently than this is refused.
- `advisories`: `malicious` refuses versions that a `MAL-` advisory lists. `all` refuses a version that any advisory lists.
- `held` (files upstreams alone): a directory the gateway fetches and verifies each pinned file into when it starts, and serves it from, as [Maven and pinned files by their own names](#maven-and-pinned-files-by-their-own-names) describes. Without it, a pinned file is fetched and verified on each request.
- `exceptions`: admit one version through the hold. Each exception names the package, version, a reason, the review that approved it, and an `expires` date. It applies only until that date, and to the hold alone: the advisory check still refuses a malicious version.

## Clients

With the gateway at `http://via-maris:8480` and the upstream names from the example:

| Client | Setting |
| --- | --- |
| npm | `registry=http://via-maris:8480/npm/` |
| pip, uv | `index-url = http://via-maris:8480/pypi/simple/` |
| go | `GOPROXY=http://via-maris:8480/go` (the go command reaches the checksum database through the same proxy) |
| Maven, Gradle | `http://via-maris:8480/central` as the repository URL |
| apt | `deb http://via-maris:8480/apt/ubuntu <suite> main` |
| files | `http://via-maris:8480/files/<pinned name>` |

The checks differ by front end:

- **npm, PyPI, Go and Maven** are checked one version at a time.
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

## npm by its own names

npm and yarn lockfiles record each tarball's full URL, and yarn 1 fetches that URL as written whatever registry it is set to. A lock resolved at the public registry names `registry.npmjs.org` or `registry.yarnpkg.com`. `byName.npm` lets those installs reach the check with the lock unchanged. `hosts` must include the host of the upstream's `url`. The names are served on the `byName.listen` port, and reached either through a host entry or through `CONNECT`, as the PyPI names are. Each handshake is given the certificate for its server name.

- `/<package>` is the packument, rewritten as the `/<name>/` path rewrites it, except that each tarball URL is left as the upstream lists it.
- `/<package>/-/<file>.tgz` is checked as the `/<name>/` tarball path is, and is served only when a version of the package lists that file.
- Every other path is answered as the `/<name>/` path answers it.

| Client | Setting |
| --- | --- |
| npm, yarn 1 | `https-proxy=http://via-maris:8480`, `noproxy=npm.pkg.github.com` and `cafile=<bundle with the CA>` in `~/.npmrc`, with no `registry` |
| a pod or runner whose `hostAliases` map the names | `npm_config_cafile=<bundle with the CA>` |

The npm `ca` should carry name constraints permitting the npm hosts alone, so a key that leaks signs nothing but them.

## Maven and pinned files by their own names

A Gradle build names its repositories and its wrapper's distribution by URL, in `settings.gradle.kts` and `gradle-wrapper.properties`, files it shares with every machine that builds it. `byName.maven` lets those builds reach the check with both files unchanged. It answers TLS for the host of each Maven upstream in `upstreams`, of each URL in `listings`, and of each pinned file of the `files` upstream, with its own `cert`, `key` and `ca`. Those names are reached through a host entry or through `CONNECT`, as the PyPI names are. A path is served by the first of these that matches it:

- **A path under a Maven upstream's `url`** is checked as the `/<name>/` path is. Each request is checked as the package `<group>:<artifact>`, OSV's name for it, at the version its directory names.
  - `maven-metadata.xml` lists only the versions that are served, because Maven metadata has no field for a reason. `<latest>` and `<release>` naming a refused version move to the newest served version, and the `.md5`, `.sha1`, `.sha256` and `.sha512` files beside it are computed over the rewritten bytes.
  - Every other file in a version's directory is checked as that version, and a file whose name does not start with `<artifact>-<version>` is refused.
  - A version is dated by the `Last-Modified` of its `.pom`, read once with a `HEAD` and kept in memory. A `.pom` that gives no time is refused.
  - A version the upstream lacks is answered with the upstream's 404, so the build tries its next repository. A 403 would end the build's search.
  - Versions are compared in Maven's own ordering, the one OSV writes its Maven ranges in.
- **A pinned file's own URL path**, on its own host, is served from the `files` upstream's `held` directory. Every other path on that host is refused.
- **An `.xml` file under a `listings` URL** is served as fetched. An Android SDK listing names each package archive with the SHA-1 that `sdkmanager` and the Android Gradle Plugin verify, and it carries no code. Every other file under it is served only when it is pinned.

Every other path on these names is refused with 403, naming it. Gradle prints the status line's reason phrase and not the body, so the listener, which speaks HTTP/1.1 alone, writes each refusal as the reason phrase as well as the body: `Received status code 403 from server: via-maris refused org.jetbrains.kotlin:kotlin-stdlib@2.4.21: published 2026-10-08T07:57:54Z, inside the 720h0m0s release-age hold until 2026-11-07T07:57:54Z`.

The `files` upstream must have `held`. The gateway fetches each pinned file into that directory when it starts, following redirects, and keeps it only when its bytes hash to the pin, so a client never waits on the upstream. A file not held yet is refused, naming its last fetch's error, and the fetch is retried after a minute, the wait doubling after each failed retry up to an hour, so a wrong pin is not downloaded in full every minute. Once every pinned file is held, the files the configuration no longer pins are removed from the directory. A file already in the directory from an earlier start is kept when it hashes to its pin. The directory holds only what can be fetched again, so an `emptyDir` volume is enough. Its size limit should allow twice the pinned files' total size, because a changed pin is fetched in full before the file it replaces is removed.

| Client | Setting |
| --- | --- |
| Gradle on a workstation | `systemProp.https.proxyHost=localhost`, `systemProp.https.proxyPort=<port of the main listener>`, `systemProp.javax.net.ssl.trustStore=<a copy of the JDK's cacerts with the CA imported>` and `systemProp.javax.net.ssl.trustStorePassword` in `~/.gradle/gradle.properties` |
| a pod or runner whose `hostAliases` map the names | the trust store lines alone |

A JVM ignores `SSL_CERT_FILE` and trusts its own `cacerts`, so the trust store is how Gradle trusts the CA. The Maven `ca` should carry name constraints permitting the Maven names alone.

`TestGradleBuildThroughTheMavenNames` runs an Android build's Gradle wrapper and `settings.gradle.kts` from `testdata/gradle`, as that build commits them, against the real Maven Central, Google Maven and Gradle distribution host. It needs Docker and the network, so it runs only with `VIA_MARIS_GRADLE_IMAGE` set to the Gradle image to run them in. `VIA_MARIS_GRADLE_HOST` gives the address a container reaches the test at when that is not Docker's `host-gateway`, and the test listens on port 443.

## Operating

- `GET /healthz` answers 503 and names what is not ready: an ecosystem's advisory data, a Go index, the record upload, or with `byName` the TLS certificate and, with `byName.npm` or `byName.maven`, the npm or Maven TLS certificate. A pinned file not yet held does not make the gateway unready, because its upstream can be down while every other front end serves. A stale in-use set only stops fix releases from passing the hold, so the gateway stays ready.
- `GET /metrics` serves Prometheus text. With `byName`, `via_maris_tls_expiry_timestamp_seconds` gives the leaf's and the CA's expiry as Unix time, labelled `certificate="leaf"` and `certificate="ca"` (and `certificate="npm-leaf"` and `certificate="npm-ca"` with `byName.npm`, and `certificate="maven-leaf"` and `certificate="maven-ca"` with `byName.maven`), and 0 before a pair has loaded. `via_maris_pinned_unheld` counts, for each files upstream with `held`, the pinned files not yet held.

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

## The egress observer

`via-maris egress-observe <egress-observe.json>` counts what Cilium egress policies observed with `enableDefaultDeny.egress: false` would refuse once enforced. [`egress-observe.example.json`](../egress-observe.example.json) carries every field: `listen` for `/metrics`, `relay` for Hubble's relay as `host:port`, and `policies`, one CiliumNetworkPolicy per namespace.

It runs in a pod and reads each policy from the API server as the pod's service account. A Role that names the policy by `resourceNames` is enough: the observer lists and watches with the field selector `metadata.name=<policy>`, which such a grant requires, and applies each change the watch reports. When the API server ends a watch, the observer lists the policy again and watches from there. It reads the policy's `spec.endpointSelector.matchLabels` and the `rules.dns` of every `spec.egress[].toPorts[]`, and refuses a policy with `specs` or a selector with `matchExpressions`.

It follows the relay over gRPC on unencrypted HTTP/2 for the policy verdicts and L7 records of each namespace's pods, keeps the events of pods the policy selects, and counts two kinds:

- `dns`: a DNS request whose name none of the policy's DNS rules matches, matched as Cilium matches `matchName` and `matchPattern`. Enforced, it gets Cilium's DNS reject answer.
- `connection`: an egress connection whose policy verdict names `allow-any-egress`, the rule Cilium adds when default deny is off. Enforced, it is dropped. It is labelled with the destination's DNS name, or its address when it has none.

`GET /metrics` serves `via_maris_egress_unlisted_total{policy_namespace,kind,destination}` and `via_maris_egress_lost_events_total{source}`. `policy_namespace` names the namespace a policy covers; it is not `namespace` because a Kubernetes pod scrape sets `namespace` to the observer's own and moves the exported value to `exported_namespace`. Each namespace and kind holds at most 256 destinations; a further one is counted under `destination="other"` and logged. The `other` series exists for every namespace and kind from the start, so each namespace shows before its first event.

The lost-events counter holds the events the relay reports lost, labelled with where Cilium dropped them, by the `LostEventSource` names in Cilium v1.19.0's `api/v1/flow/flow.proto`: `PERF_EVENT_RING_BUFFER` (the agent fell behind the datapath), `OBSERVER_EVENTS_QUEUE` (Hubble's events queue was full), `HUBBLE_RING_BUFFER` (a reader fell behind Hubble's ring buffer) or `UNKNOWN_LOST_EVENT_SOURCE`. A source value past those four, such as one a later Cilium adds, is counted under `source="other"`, so the label never holds more than five values. All five show from the start at 0.

The observer exits non-zero when the relay stream ends or sends a message it cannot parse, or when a policy is deleted, cannot be read, or changes to one it refuses, so each shows as the observer down.

## The hold-lag report

`via-maris hold-lag <hold-lag.json> [YYYY-MM]` measures one calendar month and exits. Without a month it reads the month before the run, so a scheduler runs it on the first of each month. [`hold-lag.example.json`](../hold-lag.example.json) carries every field: `gateway`, the path of the gateway's own configuration; `goWindow`; `alertmanager`; and `alertFor`. From the gateway's file it reads only `advisories.source`, `records` and `upstreams`, so it needs the records store's key alone. Each checked ecosystem's upstreams must share one hold, and that hold is what the report measures. `goWindow` must exceed the Go hold, so that a Go version first served before the window is known to have passed it.

For each of npm, PyPI, Maven and Go the run:

1. Reads the OSV export and takes every `MAL-` entry whose `published` falls in the month. Each version an entry names is listed at the earliest such entry. An entry that names its package by range alone dates nothing and is counted apart.
2. Dates each version's publication. npm uses the packument's `time`, PyPI the earliest `upload-time` among the version's files on the simple page, and Maven the `.pom`'s `Last-Modified`, trying the ecosystem's upstreams in order. For Go it reads `index.golang.org` from `goWindow` before the month to its head, keeping only the listed versions. Where none of those gives a time, the run uses the earliest `published` among the decision records the store holds. A Go version still missing that the proxy's `cached-only` path holds was first served before the window, so its lag is known only to be at least the time from the window's start to its listing. A version nothing dates is counted as undated. A version published after its listing was added to the entry later, and is counted apart.
3. Counts the dated versions whose lag passed the hold, which were still unlisted when it ended, and their share of the dated versions. The share is out of band when it passes 25% or falls below 15%. It also names the shortest whole number of days that leaves 20% or less unlisted, unless reaching it would pass a Go version's lower bound.

A month with fewer than 100 dated versions is thin: it is never out of band, and the report notes that PyPI's and Maven's holds follow npm's. Where Go's shortest hold is longer than its hold, the report notes that the gateway reads its Go index over the hold before `/healthz` reports ready, so a longer hold lengthens that start-up. Each ecosystem that is out of band gets one `ViaMarisHoldLagOutOfBand` alert, posted to `alertmanager` at severity `ticket` with its ecosystem and month as labels and ending `alertFor` after the run. Its description names the shortest hold and the `gateway` file that sets the hold. `alertFor` should run past the next month's report.

The report is written to stdout as JSON, with one log line per ecosystem. Any failure exits non-zero: a month that has not ended, an export, registry or store that cannot be read, or an alert Alertmanager refuses. A registry's 404 is not a failure, because it means the version is gone.
