# Image de la centralisatrice : binaire statique (SQLite pur Go), sans shell.
# Construction depuis extensions/centralisation-materiel : docker build -f deploy/Dockerfile .
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/centralisation-materiel ./cmd/centralisation-materiel \
 && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/centralisation-materiel /usr/local/bin/centralisation-materiel
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/centralisation-materiel
USER nonroot
ENV LISTEN=0.0.0.0:8090 DATA_DIR=/var/lib/centralisation-materiel
VOLUME ["/var/lib/centralisation-materiel"]
EXPOSE 8090
# Pas de HEALTHCHECK : image sans shell ; la santé est sondée par IRUNDO (health_url) et le proxy.
ENTRYPOINT ["/usr/local/bin/centralisation-materiel"]
