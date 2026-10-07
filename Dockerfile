# The relay as a container image, for Cloud Run or any container host.
#
#   docker build --build-arg VERSION=v0.3.0 -t san_vpn .
#   docker run -e PORT=8080 -e SAN_VPN_STATE=gs://<bucket> -p 8080:8080 san_vpn
#
# It runs `san_vpn relay run`, listening on $PORT, which Cloud Run sets. The
# relay's file must outlive the container: keep it in Cloud Storage with a
# gs:// SAN_VPN_STATE, or on a mounted volume. SAN_VPN_SESSION_LIMIT should
# match the front's request timeout, so members renew before it cuts them.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION}" -o /out/san_vpn ./cmd/san_vpn

# CA certificates for Cloud Storage, nothing else; runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/san_vpn /san_vpn
ENTRYPOINT ["/san_vpn", "relay", "run"]
