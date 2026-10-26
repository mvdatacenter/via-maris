# The gateway is built from the Go standard library alone, so its build
# downloads no module.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
WORKDIR /src
COPY go.mod *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /via-maris .

# `via-maris recheck` lists locked versions with OSV-Scanner. Its modules are
# checked against the Go checksum database as they download.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS osv-scanner
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath -ldflags="-s -w" github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /via-maris /via-maris
COPY --from=osv-scanner /out/osv-scanner /osv-scanner
USER 65532:65532
EXPOSE 8480 8443
ENTRYPOINT ["/via-maris"]
CMD ["/etc/via-maris/config.json"]
