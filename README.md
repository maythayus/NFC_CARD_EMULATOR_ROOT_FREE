# NFC CARD EMULATOR ROOT FREE

Application Android de test et d’analyse NFC, orientée **HCE ISO-DEP** (APDU), avec gestion de profils de cartes et import de dumps MIFARE Classic (pour comparaison/diagnostic).

## Fonctionnalités

- Gestion de profils de cartes
  - Ajouter / supprimer des cartes
  - Sélection d’une carte active
  - Backup / restore des profils via JSON
- Import de dumps
  - Import de dumps **VIGIK JSON** (format `vigik_badge_*.json` généré par `tools/vigik_verify.py read`)
  - Import de dumps **Proxmark3 mfcard JSON** (ex: `hf-mf-XXXX-dump.json` avec `Card.UID` + `blocks`)
  - Import de dumps bruts (`.dump` 1K) et encapsulation en wrapper raw/base64
- Émulation HCE ISO-DEP (Host Card Emulation)
  - Réponses APDU compatibles avec `tools/vigik_verify.py hce` :
    - `SELECT AID`
    - `GET UID (00CA)`
    - `READ (00B2 sector/block)` renvoyant 16 octets depuis le dump attaché
  - Protocole propriétaire de démonstration (AES-GCM)
    - AID: `F04E4643454D5531` ("NFCEMU1")
    - Script de test PC/SC: `tools/isodep_proto_verify.py`
- Logs intégrés dans l’application
  - Affichage, copie, effacement, export (SAF)

## Compatibilité VIGIK / VIGIK+

Cette application **ne clone pas** un badge VIGIK et ne met pas en œuvre l’authentification **MIFARE Classic Crypto-1**.

- **Compatible (tests PC/SC / ACR122U)** :
  - La partie **HCE ISO-DEP** fonctionne pour des lecteurs/systèmes qui acceptent un échange de type **APDU**.
  - Le script `tools/vigik_verify.py hce` permet de vérifier que le téléphone répond correctement aux commandes APDU (SELECT/UID/READ) à partir d’un dump importé.

- **Limitations importantes (VIGIK / VIGIK+)** :
  - Beaucoup d’installations VIGIK/VIGIK+ reposent sur **MIFARE Classic** et donc sur **Crypto-1**.
  - Dans ce cas, un lecteur attend une authentification Crypto‑1 (pas de trames APDU ISO‑DEP) et **Android HCE standard ne peut pas émuler cela**.

En résumé :
- Si ton portail/lecteur utilise **ISO-DEP/APDU** : les tests HCE ont de bonnes chances d’être concluants.
- Si ton portail/lecteur utilise **MIFARE Classic (Crypto‑1)** : la HCE ISO‑DEP seule ne suffira pas.

## Pré-requis

- Android: recommandé Android 11+
- NFC activé
- PC (Windows) + lecteur **ACS ACR122U** (pour les scripts outils)
- Python 3

### Dépendances Python

```bash
pip install pyscard pycryptodome
```

## Utilisation

### 1) Importer un dump

Dans l’application :
- Importer un `vigik_badge_*.json` (recommandé)
- ou un `hf-mf-XXXX-dump.json` (Proxmark3)
- ou un `.dump` brut

Attacher le dump à la carte active (ou auto-attach/auto-restore selon les cas).

### 2) Tester l’émulation HCE (mode "vigik")

Depuis `tools/`:

```bash
python vigik_verify.py hce
```

### 3) Tester le protocole propriétaire AES-GCM

Depuis `tools/`:

```bash
python isodep_proto_verify.py
```

## Notes de sécurité

- Ne pas stocker de secrets en dur (clé AES) dans une application de production.
- Le protocole AES-GCM fourni ici est une démonstration technique pour un système que **tu contrôles** (lecteur + application), pas un contournement de systèmes existants.

## Licence

Projet fourni à des fins de test/diagnostic et d’apprentissage.
