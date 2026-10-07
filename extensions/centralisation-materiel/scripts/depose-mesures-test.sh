#!/usr/bin/env bash
# Dépose des mesures matérielles de TEST dans un IRUNDO, par la route de relais de D.2
# (contrat-mesures-materielles-v1.md § 4 : POST {IRUNDO}/api/sambaedu/extension-relay/{instance},
# enveloppe se5-extension-relay/v1, jeton du handshake de l'instance). Sert à valider la
# centralisatrice sans SE5 ni collectrice (story EXT-D.4, AC5). Jamais en production.
#
# Variables :
#   IRUNDO_URL   adresse d'IRUNDO (APP_URL, préfixe de chemin compris, sans « / » final)
#   INSTANCE     uuid de l'instance (enrôlée, du périmètre de la centralisatrice)
#   TOKEN_FILE   fichier contenant l'api_token de l'instance ; à défaut, le jeton est lu sur
#                l'entrée standard. Jamais en argument (visible dans `ps`).
#
# Options :
#   --profile vm|physical|redfish   charge de départ (exemples publics de D.2, testdata/hardware/)
#   --count N                       N messages dans le lot (1 à 50), collectés toutes les 5 min
#   --message-id UUID               impose le message_id (rejeu ; avec --count 1 seulement)
#   --sources JSON                  remplace la clé sources (ex. '{"local":"ok","redfish":"unauthorized"}')
#   --degrade disk-smart|md-degraded|psu|fs-full|edac-ue   lève un signal (option répétable)
#   --extension-key KEY             extension productrice (défaut : collectrice-materiel)
#   --dry-run                       affiche l'enveloppe sans l'envoyer (ni jeton ni réseau)
#
# Sortie : « HTTP <statut> batch_id=<uuid> message_id=<uuid>… » ; code de sortie 0 sur 202.
set -euo pipefail

ici="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
donnees="${ici}/../testdata/hardware"

profile=vm
count=1
message_id=""
sources=""
degrades=()
extension_key="collectrice-materiel"
dry_run=0

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "depose-mesures-test : $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile="${2:-}"; shift 2 ;;
    --count) count="${2:-}"; shift 2 ;;
    --message-id) message_id="${2:-}"; shift 2 ;;
    --sources) sources="${2:-}"; shift 2 ;;
    --degrade) degrades+=("${2:-}"); shift 2 ;;
    --extension-key) extension_key="${2:-}"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --token|--token=*) die "le jeton ne se passe jamais en argument : TOKEN_FILE ou entrée standard" ;;
    -h|--help) usage ;;
    *) die "option inconnue : $1" ;;
  esac
done

command -v jq >/dev/null || die "jq est requis"
case "$profile" in vm|physical|redfish) ;; *) die "--profile : vm, physical ou redfish" ;; esac
[[ "$count" =~ ^[0-9]+$ ]] && [ "$count" -ge 1 ] && [ "$count" -le 50 ] || die "--count : 1 à 50"
if [ -n "$message_id" ]; then
  [ "$count" -eq 1 ] || die "--message-id impose un seul message (--count 1)"
  [[ "$message_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "--message-id : uuid attendu"
fi
if [ -n "$sources" ]; then
  jq -e 'type == "object"' <<<"$sources" >/dev/null 2>&1 || die "--sources : objet JSON attendu"
fi
[ -n "${INSTANCE:-}" ] || die "INSTANCE : uuid de l'instance obligatoire"
[[ "$INSTANCE" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "INSTANCE : uuid attendu"

uuid4() {
  if [ -r /proc/sys/kernel/random/uuid ]; then cat /proc/sys/kernel/random/uuid
  elif command -v uuidgen >/dev/null; then uuidgen | tr 'A-Z' 'a-z'
  else die "ni /proc/sys/kernel/random/uuid ni uuidgen"
  fi
}

# Altérations : chacune lève un signal du modèle d'état de la centralisatrice.
filtre_degrade() {
  case "$1" in
    disk-smart) echo '.disk = ((.disk // [{"name":"sda","model":"TEST","serial_masked":"","size_b":1000204886016,"rotational":true,"transport":"sata","driver":"ahci"}])
                 | (.[0].smart = {"passed":false,"power_on_h":40000,"reallocated":12,"pending":3,"uncorrectable":1,"pct_used":0,"media_errors":0,"critical_warning":0}))' ;;
    md-degraded) echo '.md = [{"name":"md0","level":"raid1","array_state":"clean","degraded":true,"raid_disks":2,"sync_action":"idle","sync_pct":100,"mismatch":0}]' ;;
    psu) echo '.sources.redfish = "ok" | .redfish.power = {"supplies":[{"name":"PS1 Status","health":"OK"},{"name":"PS2 Status","health":"Critical"}],"redundancy":"Degraded","consumed_w":180}' ;;
    fs-full) echo '.fs = ((.fs // [{"mount":"/","fstype":"ext4","size_b":100000000000,"used_b":0,"inodes_used_pct":10}]) | (.[0].used_b = ((.[0].size_b * 0.98) | floor)))' ;;
    edac-ue) echo '.mem.edac = [{"mc":"mc0","ce":4,"ue":1,"size_b":34359738368}]' ;;
    *) die "--degrade : disk-smart, md-degraded, psu, fs-full ou edac-ue" ;;
  esac
}

payload="$(cat "${donnees}/${profile}.json")"
for d in "${degrades[@]+"${degrades[@]}"}"; do
  payload="$(jq -c "$(filtre_degrade "$d")" <<<"$payload")"
done
if [ -n "$sources" ]; then
  payload="$(jq -c --argjson s "$sources" '.sources = $s' <<<"$payload")"
fi

now="$(date -u +%s)"
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
messages="[]"
ids=()
for ((i = 0; i < count; i++)); do
  id="${message_id:-$(uuid4)}"
  ids+=("$id")
  collected="$(iso $((now - (count - 1 - i) * 300)))"
  messages="$(jq -c --arg id "$id" --arg at "$collected" --argjson p "$payload" \
    '. + [{"message_id": $id, "kind": "hardware/v1", "collected_at": $at, "payload": $p}]' <<<"$messages")"
done
envelope="$(jq -n --arg inst "$(tr 'A-Z' 'a-z' <<<"$INSTANCE")" --arg key "$extension_key" --arg sent "$(iso "$now")" --argjson m "$messages" \
  '{"schema_version":"1.0","instance_id":$inst,"extension":{"key":$key,"version":"test"},"sent_at":$sent,"messages":$m}')"

if [ "$dry_run" -eq 1 ]; then
  printf '%s\n' "$envelope"
  exit 0
fi

[ -n "${IRUNDO_URL:-}" ] || die "IRUNDO_URL : adresse d'IRUNDO obligatoire"
command -v curl >/dev/null || die "curl est requis"
if [ -n "${TOKEN_FILE:-}" ]; then
  [ -r "$TOKEN_FILE" ] || die "TOKEN_FILE illisible"
  token="$(head -n1 "$TOKEN_FILE" | tr -d '[:space:]')"
else
  [ -t 0 ] && echo "jeton de l'instance (api_token) sur l'entrée standard :" >&2
  IFS= read -r token || true
  token="$(tr -d '[:space:]' <<<"$token")"
fi
[ -n "$token" ] || die "jeton vide (TOKEN_FILE ou entrée standard)"

corps="$(mktemp)"
trap 'rm -f "$corps"' EXIT
# Le jeton passe par un fichier de configuration de curl lu sur un descripteur : jamais dans argv.
status="$(curl -sS -o "$corps" -w '%{http_code}' -X POST "${IRUNDO_URL%/}/api/sambaedu/extension-relay/${INSTANCE}" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -K <(printf 'header = "Authorization: Bearer %s"\n' "$token") \
  --data-binary @- <<<"$envelope")" || die "requête en échec (réseau)"
batch="$(jq -r '.data.batch_id // empty' "$corps" 2>/dev/null || true)"
echo "HTTP ${status} batch_id=${batch:-—} message_id=${ids[*]}"
if [ "$status" != "202" ]; then
  jq -c '.data // .' "$corps" >&2 2>/dev/null || cat "$corps" >&2
  exit 1
fi
