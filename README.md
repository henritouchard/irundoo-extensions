# irundoo-extensions

Source de catalogue d'extensions IRUNDO (format `irundoo-extensions-index` v1, voir
`documentation/extensions/irundoo-extensions-index-v1.md` dans le dépôt irundoo).

## Fichiers servis

| Fichier | Rôle |
|---|---|
| `irundoo-index.json` | index : les manifestes de `extensions/*/manifest.json`, avec `serial` |
| `irundoo-index.json.sig` | signature Ed25519 détachée (base64) des octets exacts de l'index |
| `source.pub` | clé publique Ed25519 (base64), empreinte `sha256:c168-4681-3ecc-ecf7` |

Adresse de la source (dépôt privé : jeton GitHub en lecture, envoyé en `Authorization: Bearer`) :

```
https://raw.githubusercontent.com/henritouchard/irundoo-extensions/main
```

```bash
php artisan ext:sources:add https://raw.githubusercontent.com/henritouchard/irundoo-extensions/main \
  --fingerprint=sha256:c168-4681-3ecc-ecf7 --token-stdin
```

## Publier

1. Ajouter ou modifier `extensions/<id>/manifest.json` (le dossier porte l'`id`).
2. `php scripts/publish.php --key ../extenstion-keys/irundoo-extensions.key` : reconstruit l'index, incrémente `serial`, signe et vérifie.
3. Commiter les trois fichiers ensemble, puis pousser.

Ne jamais retoucher `irundoo-index.json` après signature (`.gitattributes` empêche git de le
réécrire). La clé secrète vit hors du dépôt, sur l'hôte de publication (`--key <chemin>`, sinon
`IRUNDO_INDEX_SECRET_KEY_FILE`, défaut `~/.config/irundoo-extensions/secret.key`, ou
`IRUNDO_INDEX_SECRET_KEY`) ; la perdre oblige à publier une nouvelle clé, que chaque IRUNDO doit
retirer puis réajouter après vérification de l'empreinte.
