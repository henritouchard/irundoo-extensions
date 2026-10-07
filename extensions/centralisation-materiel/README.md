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
| relève de fond | toutes les `POLL_INTERVAL`, sous **jeton machine** (`client_credentials`, réutilisé jusqu'à `exp − 30 s`) : `/instances` puis `/hardware`, insertion des mesures nouvelles en SQLite, en une transaction (clé `(instance_id, extension_key, message_id)` : un rejeu n'ajoute rien) ; conduite des refus ci-dessous (« Relève de fond ») |
| `GET\|HEAD /health` | `200 {"version":"0.1.0"}` (version du manifeste embarqué) ; `503 {"version":…,"error":"store"}` si SQLite n'est pas utilisable ; sans authentification ni redirection ; une relève en échec ne rend **pas** `503` |
| `/oidc/login`, `/oidc/callback`, `POST /logout` | flot `authorization_code` + PKCE S256, `client_secret_basic` ; renouvellement `prompt=none`, une seule relance sans `prompt` sur `login_required`, jamais de boucle ; un cookie de tentative par `state` (deux onglets qui se renouvellent ne s'écrasent pas) ; déconnexion **locale** (IRUNDO n'a pas d'`end_session_endpoint`), en `POST` avec jeton anti-CSRF |

### États (seuils v1, `internal/etat`)

- **pas de nouvelle** : aucune entrée `/hardware` pour l'établissement, ou dernière mesure plus
  vieille que `STALE_AFTER`. L'âge se juge sur `least(collected_at, received_at)` — la date de
  collecte plafonnée à la réception, la même que celle qui fait la « dernière » mesure côté
  serveur (contrat § 6) : un vieux lot relayé tard n'a pas l'air frais, une horloge d'établissement
  en avance ne rajeunit rien. L'écran affiche cet âge (« collectée il y a … ») ; les deux dates
  sont au survol et dans le détail. **Exception** : si la dernière mesure connue était
  **critique**, la ligne reste comptée « critique » et l'écrit (« pas de nouvelle — dernier état
  connu : critique ») — le silence ne masque jamais un critique ;
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

Mentions sur la ligne, sans changer l'état :

- une **source tentée sans résultat** (`sources.<x>` ni `ok` ni `partial` : `unauthorized`,
  `absent`, `timeout`, `error`, `unreachable`, `tls`) s'écrit « source redfish : unauthorized » —
  un « sain » lu sans la carte de gestion n'est pas le même « sain » ;
- **`redfish.scope = hypervisor-host`** : la carte lue est celle de l'hôte Proxmox, partagée par
  plusieurs établissements virtualisés. Ses signaux ne font **pas** l'état de l'établissement (qui
  reste « matériel non observé » sans autre source) ; chacun de ses critiques s'écrit sur la ligne
  (« matériel de l'hôte de virtualisation (partagé) : critique — … »), et le détail les range dans
  une section « matériel de l'hôte de virtualisation (partagé, non attribué à l'établissement) ».

Une valeur de type inattendu n'est pas évaluée (comptée), jamais un « critique » par défaut. Les
compteurs remis à zéro au démarrage sont datés « depuis le démarrage du … » (`received_at −
os.uptime_s`) ; un changement de `os.boot_id` apparaît dans l'historique.

## Configuration (variables d'environnement seules)

| Variable | Obligatoire | Défaut | Rôle |
|---|---|---|---|
| `IRUNDOO_ISSUER` | oui | — | issuer OIDC d'IRUNDO, préfixe de chemin compris, sans `/` final (`https://irundo.example.org/controlhub`), **`https://` hors développement** (le secret client et les jetons y passent) ; Discovery à `{issuer}/.well-known/openid-configuration`, API à `{issuer}/api/v1/extensions` |
| `CLIENT_ID` | oui | — | identifiant remis à l'enregistrement (32 hex) |
| `CLIENT_SECRET_FILE` / `CLIENT_SECRET` | l'un des deux | — | secret (64 hex) ; **fichier 0600 préféré**, il prime ; jamais en argument, jamais journalisé |
| `PUBLIC_URL` | oui | — | adresse publique, `https://` hors développement, sans `/` final ni chemin ; `redirect_uri` = `PUBLIC_URL/oidc/callback` (aucun `X-Forwarded-*` n'est cru) |
| `LISTEN` | non | `127.0.0.1:8090` | écoute HTTP (TLS par le proxy) |
| `STATE_DIRECTORY` / `DATA_DIR` | l'un des deux | — | répertoire de `centralisation-materiel.sqlite` (0600, WAL) ; `STATE_DIRECTORY` est posé par systemd |
| `STALE_AFTER` | non | `30m` | délai au-delà duquel une mesure est « pas de nouvelle » |
| `POLL_INTERVAL` | non | `5m` (min `1m`) | cadence de la relève ; `0` la désactive (écran seul) |
| `HISTORY_RETENTION_DAYS` | non | `180` | purge locale (au démarrage puis chaque jour) |
| `LOG_LEVEL` | non | `info` | `debug`, `info`, `warn`, `error` (journal JSON sur la sortie d'erreur) |
| `DEV_INSECURE_COOKIES` | non | `false` | `true` en développement HTTP loopback seulement : autorise `PUBLIC_URL` et `IRUNDOO_ISSUER` en `http://`. L'attribut `Secure` des cookies, le préfixe `__Host-` et HSTS suivent le **schéma de `PUBLIC_URL`** (https ⇒ toujours posés), jamais ce drapeau seul |

Un démarrage refusé nomme la variable en cause. Préfixe de chemin pour la centralisatrice elle-même :
non pris en charge en v1 (elle vit à la racine de son hôte).

## Relève de fond

Conduite alignée sur `fournisseur-oidc.md` § 11.5 :

- un passage = un jeton (du cache, ou neuf) puis `/instances` et `/hardware` ;
- `401` sur un jeton **du cache** : jeton oublié, **un** jeton neuf, l'appel rejoué **une** fois
  (au plus 2 jetons + 3 appels par passage) ;
- `401` sur un jeton **neuf**, second `401`, ou `invalid_client` au `token_endpoint` (application
  révoquée, secret changé) : l'échec est consigné (bandeau « relève de fond en échec … relève
  arrêtée jusqu'au redémarrage du service »), puis la relève **cesse** — redemander un jeton à
  chaque intervalle n'y changerait rien. Corriger l'enregistrement ou le secret, puis redémarrer ;
- `400 invalid_scope` (scopes machine non accordés), `403`, `503`, réseau : passage en échec
  consigné, réessayé à l'intervalle suivant ;
- `429` : passage abandonné aussitôt ; le suivant attend `Retry-After` ;
- arrêt du service (SIGTERM) pendant un passage : rien n'est consigné ;
- un refus du `token_endpoint` est consigné par son statut et son code OAuth (liste fermée), jamais
  par son corps.

**Échantillons intermédiaires.** L'API ne sert que la **dernière** mesure par (établissement,
extension) et n'a pas de `?since=` : une relève toutes les 5 min contre une collectrice qui dépose
plus souvent (ou un lot de plusieurs messages déposé d'un coup) ne voit que la dernière de chaque
intervalle. L'historique local est un échantillonnage à la cadence de `POLL_INTERVAL`, pas la
série complète des mesures.

**Horodatages en base** : UTC à largeur fixe (`2006-01-02T15:04:05.000000000Z`), pour que l'ordre
des chaînes soit l'ordre chronologique (tri, purge). La migration `0002` réécrit les valeurs d'une
base créée par la 0.1.0.

## Sécurité de la session

- Session serveur en SQLite ; le cookie ne porte qu'un identifiant aléatoire (32 octets) :
  `__Host-cm_session` en https (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, sans `Domain`),
  `cm_session` en développement http. HSTS (`max-age=31536000`) posé en https.
- **Le jeton d'accès de l'utilisateur est stocké en clair** dans la table `sessions` (il faut le
  présenter à l'API à chaque rendu) : le fichier SQLite est en `0600`, son répertoire en `0700`
  (`StateDirectoryMode`, volume du conteneur) ; une session inutilisée 12 h est purgée, le jeton
  expire de lui-même (`expires_in` d'IRUNDO). Sauvegarder ce fichier, c'est sauvegarder des jetons
  vivants.
- Tentatives de connexion (créées sans authentification) : au plus 1000 en vol (au-delà `503`),
  purge des expirées à chaque création, et 10 par minute par adresse (rafale de 20, au-delà `429`).
  Derrière un proxy local (pair loopback), l'adresse est la dernière de `X-Forwarded-For` (celle
  que le proxy a ajoutée) ; elle ne sert qu'à cette limite.
- Déconnexion en `POST` avec un jeton anti-CSRF et, si le navigateur l'envoie, une `Origin` égale à
  `PUBLIC_URL`.

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
- **Docker** : `make docker` (`deploy/Dockerfile`, images de base épinglées par digest, image
  `distroless/static` sans shell, utilisateur `nonroot` uid/gid 65532, volume
  `/var/lib/centralisation-materiel`) ; `.dockerignore` écarte `tmp/`, `bin/`, `dev/env` et les
  secrets du contexte. Exemple `deploy/docker-compose.example.yml` : le secret `file:` est monté
  avec le propriétaire et le mode de l'hôte — `chown 65532:65532` + `chmod 600`, ou lancer le
  conteneur sous l'uid/gid propriétaire du fichier (`user:`), voir l'en-tête du fichier.
- **systemd** : `deploy/centralisation-materiel.service` (`DynamicUser`, `StateDirectory`,
  `EnvironmentFile=/etc/centralisation-materiel/env` en 0600 sans le secret, secret par
  `LoadCredential=` ⇒ `CLIENT_SECRET_FILE=%d/client_secret`, `SystemCallFilter=@system-service`,
  durcissement ; repli sans `LoadCredential` décrit en tête de l'unité), non activée par défaut.
- **Sonde de santé** : pas de `HEALTHCHECK` Docker (il exécuterait une commande dans le conteneur,
  qui n'a ni shell ni curl). Sonder de l'extérieur : IRUNDO (`health_url`, HTTPS), le proxy, ou
  l'hôte — `curl -fsS http://127.0.0.1:8090/health` (`200` sain, `503 {"error":"store"}` si SQLite
  est inutilisable) dans un timer systemd ou la supervision.
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
(répétable), `--extension-key KEY`, `--connect-timeout S`, `--max-time S` ; toutes validées avant
l'envoi. Un `IRUNDO_URL` en `http://` hors loopback est signalé. Le jeton se lit par `TOKEN_FILE` ou l'entrée standard, jamais en argument. Recette
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
