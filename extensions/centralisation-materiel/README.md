# centralisation-materiel — l'état matériel des établissements (extension IRUNDO `app`)

Service Go joignable par URL (story EXT-D.4, périmètre D.4a). Un agent de collectivité ouvre la tuile
dans IRUNDO et voit, établissement par établissement de **son périmètre** (jugé par IRUNDO à chaque
rendu), l'état matériel du serveur SambaÉdu : **critique**, **attention**, **pas de nouvelle**,
**matériel non observé** ou **sain**, avec le détail de la dernière mesure et l'historique accumulé
localement.

Écrite à partir de la **documentation publique d'IRUNDO seule** (`documentation/extensions/` du dépôt
IRUNDO : guide du développeur, `fournisseur-oidc.md`, `api-v1.md`, `openapi-v1.json`,
`contrat-mesures-materielles-v1.md`, `sante-extensions.md`, manifeste) ; elle ne connaît d'IRUNDO que
l'API `{issuer}/api/v1/extensions` et le fournisseur OIDC lu par la Discovery.

## Ce qu'elle fait

| Chemin | Rôle |
|---|---|
| écran (`GET /`) | à chaque rendu, deux appels **avec le jeton de l'utilisateur** : `GET /instances` (source unique des lignes) puis `GET /hardware` ; état calculé par ligne ; aucune ligne ajoutée depuis la base locale |
| détail (`GET /etablissements/{id}`, htmx) | la dernière mesure dépliée (sources, OS, CPU, mémoire, volumes, disques, RAID, Redfish, Proxmox) et l'historique local (mesures conservées, redémarrages, signaux passés) ; un id absent de `/instances` ⇒ `404`, jamais d'appel `?instance=` |
| relève de fond | toutes les `POLL_INTERVAL`, sous **jeton machine** (`client_credentials`, réutilisé jusqu'à `exp − 30 s`) : `/instances` puis `/hardware`, insertion des mesures nouvelles en SQLite (clé `(instance_id, extension_key, message_id)` : un rejeu n'ajoute rien) ; au plus un jeton + deux appels par passage, aucun retry immédiat |
| `GET\|HEAD /health` | `200 {"version":"0.1.0"}` (version du manifeste embarqué) ; `503 {"version":…,"error":"store"}` si SQLite n'est pas utilisable ; sans authentification ni redirection ; une relève en échec ne rend **pas** `503` |
| `/oidc/login`, `/oidc/callback`, `/logout` | flot `authorization_code` + PKCE S256, `client_secret_basic` ; renouvellement `prompt=none`, une seule relance sans `prompt` sur `login_required`, jamais de boucle ; déconnexion **locale** (IRUNDO n'a pas d'`end_session_endpoint`) |

### États (seuils v1, `internal/etat`)

- **pas de nouvelle** : aucune entrée `/hardware` pour l'établissement, ou `received_at` (horloge
  d'IRUNDO, jamais `collected_at`) plus vieux que `STALE_AFTER` ;
- **critique** / **attention** : un signal levé — RAID md dégradé, SMART échoué, secteurs non
  corrigibles, panne prédite, alimentation ou redondance dégradée, santé Redfish `Critical`, erreur
  mémoire non corrigée, volume plein à 97 % (critique) ; secteurs réalloués, usure ≥ 90 %, vie
  restante ≤ 10 %, erreurs d'E/S, ventilateur ou température hors `OK`, événement SEL critique de
  moins de 7 jours, erreurs mémoire corrigées, température ≥ `crit` (ou 85 °C), volume ou inodes
  à 90 %, mémoire disponible < 5 % (attention) ;
- **matériel non observé** : mesure fraîche, aucun signal, `host.profile` ≠ `physical` et aucune
  source matérielle (`sources.redfish` / `sources.pve`) à `ok` ou `partial` — une VM sans carte de
  gestion ne s'affiche jamais « saine » ;
- **sain** sinon (mention « disques derrière contrôleur : inventaire seulement » pour un serveur
  physique sans SMART).

Une valeur de type inattendu n'est pas évaluée (comptée), jamais un « critique » par défaut. Les
compteurs remis à zéro au démarrage sont datés « depuis le démarrage du … » (`received_at −
os.uptime_s`) ; un changement de `os.boot_id` apparaît dans l'historique.

## Configuration (variables d'environnement seules)

| Variable | Obligatoire | Défaut | Rôle |
|---|---|---|---|
| `IRUNDOO_ISSUER` | oui | — | issuer OIDC d'IRUNDO, préfixe de chemin compris, sans `/` final (`https://irundo.example.org/controlhub`) ; Discovery à `{issuer}/.well-known/openid-configuration`, API à `{issuer}/api/v1/extensions` |
| `CLIENT_ID` | oui | — | identifiant remis à l'enregistrement (32 hex) |
| `CLIENT_SECRET_FILE` / `CLIENT_SECRET` | l'un des deux | — | secret (64 hex) ; **fichier 0600 préféré**, il prime ; jamais en argument, jamais journalisé |
| `PUBLIC_URL` | oui | — | adresse publique, `https://` hors développement, sans `/` final ni chemin ; `redirect_uri` = `PUBLIC_URL/oidc/callback` (aucun `X-Forwarded-*` n'est cru) |
| `LISTEN` | non | `127.0.0.1:8090` | écoute HTTP (TLS par le proxy) |
| `STATE_DIRECTORY` / `DATA_DIR` | l'un des deux | — | répertoire de `centralisation-materiel.sqlite` (0600, WAL) ; `STATE_DIRECTORY` est posé par systemd |
| `STALE_AFTER` | non | `30m` | délai au-delà duquel une mesure est « pas de nouvelle » |
| `POLL_INTERVAL` | non | `5m` (min `1m`) | cadence de la relève ; `0` la désactive (écran seul) |
| `HISTORY_RETENTION_DAYS` | non | `180` | purge locale (au démarrage puis chaque jour) |
| `LOG_LEVEL` | non | `info` | `debug`, `info`, `warn`, `error` (journal JSON sur la sortie d'erreur) |
| `DEV_INSECURE_COOKIES` | non | `false` | `true` en développement HTTP loopback seulement (cookies sans `Secure`, `PUBLIC_URL` en `http://`) |

Un démarrage refusé nomme la variable en cause. Préfixe de chemin pour la centralisatrice elle-même :
non pris en charge en v1 (elle vit à la racine de son hôte).

## Enregistrer l'application dans IRUNDO

Gestes de l'administrateur, documentés dans l'aide d'IRUNDO (`/doc/admin/extensions/`) et résumés au
§ 15 du guide du développeur :

1. **Ajouter la source** `irundoo-extensions` (empreinte de la clé dans le README racine), puis
   **retenir** `centralisation-materiel` dans la bibliothèque — « Retenir et intégrer ».
2. **Enregistrer comme client** — « Enregistrer une application » : copier `client_id` et le secret
   (affiché une fois) dans `CLIENT_ID` et `CLIENT_SECRET_FILE`.
3. **Périmètre et droits** — « Octroyer un périmètre » : cocher les contrats, et
   `irundoo:instances:read` + `irundoo:hardware:read` **dans les deux familles** (utilisateur connecté
   et jeton machine) ; en ligne de commande :
   `php artisan ext:perimeter:set centralisation-materiel --contract=<uuid> --user-scope=irundoo:instances:read --user-scope=irundoo:hardware:read --machine-scope=irundoo:instances:read --machine-scope=irundoo:hardware:read`.
4. **Visibilité** de la tuile : les statuts qui l'ouvrent — « Connecter une application ».

Si un droit n'est pas accordé côté utilisateur, l'écran l'écrit (« droit non accordé par
l'administrateur : … ») ; côté machine, la relève s'affiche en échec dans un bandeau, l'écran reste
servi.

## Déploiement

- **Binaire** : `make build` ⇒ `bin/centralisation-materiel`, statique (`CGO_ENABLED=0`, SQLite pur
  Go `modernc.org/sqlite`).
- **Docker** : `make docker` (`deploy/Dockerfile`, image `distroless/static` sans shell, utilisateur
  `nonroot`, volume `/var/lib/centralisation-materiel`) ; exemple `deploy/docker-compose.example.yml`.
- **systemd** : `deploy/centralisation-materiel.service` (`DynamicUser`, `StateDirectory`,
  `EnvironmentFile=/etc/centralisation-materiel/env` en 0600, durcissement), non activée par défaut.
- **TLS** : un proxy devant (`deploy/Caddyfile.example`, nginx en commentaire). `entry_url` et
  `health_url` sont en HTTPS avec un certificat que le conteneur IRUNDO reconnaît (la sonde vérifie
  le TLS, ne suit aucune redirection, refuse le loopback).

Avant publication, remplacer `centralisation-materiel.example.org` dans `manifest.json` par l'adresse
réelle (`entry_url`, `redirect_uris`, `health_url`), puis `php scripts/publish.php` à la racine du
dépôt (clé de signature de l'éditeur, hors dépôt). Toute modification du manifeste est une nouvelle
version à reprendre dans IRUNDO ; une nouvelle `redirect_uri` n'est admise qu'après « Reprendre les
adresses publiées » : servir l'ancienne et la nouvelle pendant l'intervalle (guide § 18).

## Développement local

1. Dans l'IRUNDO de développement (`APP_ENV=local`) : **Ajouter › Saisie manuelle** avec
   `dev/manifest.dev.json` (`id: centralisation-materiel-dev`, retour `http://127.0.0.1:8090/oidc/callback`),
   retenir, enregistrer comme client, octroyer comme ci-dessus. Ce manifeste n'est **jamais** publié.
2. `cp dev/env.example dev/env`, y mettre `CLIENT_ID` ; le secret dans `tmp/client_secret` (0600).
3. `make run-dev`, puis ouvrir **`http://127.0.0.1:8090/`** directement (la tuile pointe
   l'`entry_url` HTTPS fictive du manifeste de dev). La sonde de santé d'IRUNDO refuse le loopback :
   la tuile dit « injoignable » en dev, c'est attendu ; vérifier à la main :
   `curl -si http://127.0.0.1:8090/health`.

### Déposer des mesures de test

`scripts/depose-mesures-test.sh` dépose une enveloppe `se5-extension-relay/v1` par la route de relais
d'IRUNDO, sous le jeton du handshake d'une instance — sans SE5 ni collectrice :

```bash
export IRUNDO_URL=http://local.irundoo.fr:3000 INSTANCE=<uuid> TOKEN_FILE=./tmp/token_instance   # 0600
scripts/depose-mesures-test.sh --profile vm                      # ⇒ « matériel non observé »
scripts/depose-mesures-test.sh --profile redfish                 # ⇒ critique (PSU, panne prédite)
scripts/depose-mesures-test.sh --profile physical --degrade md-degraded
scripts/depose-mesures-test.sh --profile physical --message-id <uuid>   # rejeu : aucune mesure nouvelle
scripts/depose-mesures-test.sh --profile vm --dry-run | jq .     # enveloppe seule, sans envoi
```

Options : `--count N`, `--sources '{…}'`, `--degrade disk-smart|md-degraded|psu|fs-full|edac-ue`
(répétable). Le jeton se lit par `TOKEN_FILE` ou l'entrée standard, jamais en argument. Recette
complète : `docs/qa/domains/extensions.md` § 25 du dépôt IRUNDO.

## Développer

```bash
make test       # go test ./... : sans réseau, faux IRUNDO construit d'après la doc (internal/fakeirundo)
make lint       # go vet + gofmt
make generate   # client API depuis testdata/openapi-v1.json (oapi-codegen v2.8.0)
```

- `testdata/` : copies **datées** des schémas, de la spécification et des exemples publics d'IRUNDO
  (`testdata/ORIGINE.md`) ; les recopier quand le contrat évolue (ajout seul).
- Les tests vérifient : le manifeste contre son schéma (moteur ECMAScript : les motifs du schéma
  emploient `(?=…)`, que le `regexp` de Go refuse), la liste blanche des modules (`deps_test.go`),
  qu'aucun chemin d'IRUNDO autre que la Discovery n'est codé, que le journal ne contient ni secret ni
  jeton.
- **htmx 2.0.10** embarqué (`internal/web/static/htmx.min.js`, sha256
  `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de`, unpkg `htmx.org@2.0.10`) ;
  aucune ressource externe, `Content-Security-Policy: default-src 'self'`.

## Ce qui viendra (D.4b)

Tendances tracées sur l'historique, seuils réglables, alertes, export, préfixe de chemin.
