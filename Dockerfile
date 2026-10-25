# The gateway is built from the Go standard library alone, so this build
# downloads no module.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
WORKDIR /src
COPY go.mod *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /via-maris .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /via-maris /via-maris
USER 65532:65532
EXPOSE 8480
ENTRYPOINT ["/via-maris"]
CMD ["/etc/via-maris/config.json"]
