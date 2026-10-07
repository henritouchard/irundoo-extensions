# Image de la centralisatrice : binaire statique (SQLite pur Go), sans shell.
# Construction depuis extensions/centralisation-materiel : docker build -f deploy/Dockerfile .
# (.dockerignore écarte tmp/, bin/, dev/env et tout fichier de secret du contexte.)
# Images de base épinglées par digest (index multi-architecture, résolus le 2026-10-07 par
# `docker buildx imagetools inspect`) : un retag amont ne change pas l'image construite. Mettre à
# jour : relire le digest du tag et remplacer.
FROM golang:1.27-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/centralisation-materiel ./cmd/centralisation-materiel \
 && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/centralisation-materiel /usr/local/bin/centralisation-materiel
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/centralisation-materiel
USER nonroot
ENV LISTEN=0.0.0.0:8090 DATA_DIR=/var/lib/centralisation-materiel
VOLUME ["/var/lib/centralisation-materiel"]
EXPOSE 8090
# Pas de HEALTHCHECK : il exécuterait une commande dans le conteneur, et l'image n'a ni shell ni
# curl (distroless). La santé se sonde de l'extérieur : IRUNDO (health_url, HTTPS), le proxy, ou
# l'hôte (`curl -fsS http://127.0.0.1:8090/health`, cf. README « Sonde de santé »).
ENTRYPOINT ["/usr/local/bin/centralisation-materiel"]
