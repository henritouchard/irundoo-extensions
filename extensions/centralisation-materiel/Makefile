# Centralisatrice matérielle (extension IRUNDO, story EXT-D.4).
BIN      := bin/centralisation-materiel
VERSION  := $(shell sed -n 's/.*"extension_version": *"\([^"]*\)".*/\1/p' manifest.json)
LDFLAGS  := -s -w   # la version vient du manifeste embarqué (une seule source)

.PHONY: build test lint generate run-dev docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/centralisation-materiel

test:
	go test ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && false)

# Régénère le client API depuis testdata/openapi-v1.json (copie datée de la spécification d'IRUNDO).
generate:
	go generate ./internal/irundoo/irundooapi

# Développement local contre l'IRUNDO de dev : dev/env (copie de dev/env.example, non commitée).
run-dev:
	@test -f dev/env || (echo "créer dev/env depuis dev/env.example" && false)
	mkdir -p tmp
	set -a && . ./dev/env && set +a && go run ./cmd/centralisation-materiel

docker:
	docker build -f deploy/Dockerfile -t centralisation-materiel:$(VERSION) .

clean:
	rm -f $(BIN)
