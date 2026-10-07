# Origine des copies de `testdata/`

Copies **à l'identique** de la documentation publique d'IRUNDO (dépôt `irundoo`,
`documentation/extensions/`), prises le **2026-10-07** au commit `040f6da` de la branche
`ultradev/ext-D-4` (D.2 fusionnée). Ne pas éditer : recopier depuis IRUNDO quand le contrat change
(ajout seul, NFR9), puis `make generate` pour le client API.

| Copie | Origine |
|---|---|
| `irundoo-extension-manifest-v1.schema.json` | `documentation/extensions/irundoo-extension-manifest-v1.schema.json` |
| `openapi-v1.json` | `documentation/extensions/openapi-v1.json` (spécification générée, EXT-C.8 / D.2) |
| `hardware-v1.schema.json` | `documentation/extensions/hardware-v1.schema.json` (contrat D.2 § 5) |
| `se5-extension-relay-v1.schema.json` | `documentation/extensions/se5-extension-relay-v1.schema.json` (contrat D.2 § 4, pour le script de dépôt) |
| `hardware/vm.json`, `physical.json`, `redfish.json` | `documentation/extensions/examples/hardware/` (charges `hardware/v1`) |
| `hardware/relay-envelope.json`, `deposit.json` | idem (enveloppe `se5-extension-relay/v1`, dépôt) |

Empreintes sha256 au moment de la copie :

```
ddd1b8ce93d8ef17bec2ee0497c300bd506c60d9306efbd01687e163dac71b41 testdata/hardware-v1.schema.json
7634515594229a80e6285c9cb1164a7191c6a83e10a5133502f56a913d3d2a9b testdata/irundoo-extension-manifest-v1.schema.json
0e0689f2546c1b5970481b2056db705e601b8449d1729dfb94ff24856c5f97b2 testdata/openapi-v1.json
b2afddd73c428fd34ca5e46f0c436a91af67680aa81b9c5491e399dea4d6120f testdata/hardware/deposit.json
e3f308161c045bbf1cf238b5060e1f99891869cb382e4801fe7c0e09c180befe testdata/hardware/physical.json
829cdcc51daed6ab2fe525d01a00cedb8e37b2febff2b126a0d41090a1484735 testdata/hardware/redfish.json
014bd2764352b8389e3aa76bd53ad274e942ba78392742abc3834221dcb17cb1 testdata/hardware/relay-envelope.json
4f8fef59cfcbbc48c06a44a774a214b1dacf71aa0857feea2e09700d3685342c testdata/hardware/vm.json
e028d428ddf7632f39bf08b0bdabffb8531f3520e6868d9bf47b4ec0af266a1c testdata/se5-extension-relay-v1.schema.json
```
