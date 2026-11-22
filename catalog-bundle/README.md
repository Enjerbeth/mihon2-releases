# Mihon Declarative Catalog Bundle (v2)

Self-contained declarative catalog bundle for **Instant Sources (No APK)** using schema v2 (`entries` + lazy per-recipe JSON files under `recipes/`).

This directory is 100% decoupled and portable: you can copy its contents into a brand-new repository (`git init`), host it on GitHub or any HTTPS static host, and add its raw `index.json` URL inside the app under **Repositories**.

## Structure

- `index.json`: Lightweight v2 index (`schemaVersion: 2`) containing `entries` with metadata and `recipePath` pointers (no inline recipe payloads).
- `recipes/<sourceId>.json`: Individual v2 declarative source recipes (`schemaVersion: 2`, `mode: "declarative"`).
- `schema/`: JSON Schema (Draft 2020-12) definitions for `catalog-index.v2.schema.json` and `source-recipe.v2.schema.json`.
- `tools/sync_catalog.py`: Synchronizes recipes and `index.json` from upstream protobuf indexes and shallow `git clone --depth 1` source checkouts, verifying OSI licenses (`Apache-2.0` / `MIT`), deduplicating cross-repo entries by `(lang, domain)` + `sourceId` (highest `versionCode` wins), generating `NOTICE`, and running HTTP smoke tests (`>= 3` items required before `ACTIVE`).
- `tools/validate_catalog.py`: Validates v2 index coherence, recipe safety (strict HTTPS port-443 SSRF policy, structural nested-quantifier ReDoS guard, header/pipeline limits, BCP-47 language tags), fixtures, `NOTICE`, and bundle isolation.
- `deprecated_sources.json`: Blocklist of retired or broken upstream sources.
- `fixtures/`: Sample HTML/JSON payloads for offline validation and tests.
- `tests/`: Standalone unit & isolation tests.
- `LICENSE` / `NOTICE`: Apache-2.0 license and generated third-party attributions.

## Local Usage

```bash
pip install -r requirements.txt
python -B -m unittest discover -s tests -v
python -B tools/validate_catalog.py
```

To synchronize against upstream sources:

```bash
python -B tools/sync_catalog.py --clone-upstreams --apply --probe-live
```

## Using in the App

1. Host this repository on GitHub (or another HTTPS host).
2. Copy the raw HTTPS URL to `index.json`, for example:
   `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/index.json`
3. Open **Repositories** in the app and paste the URL. No sources are activated automatically until you tap **Activar sin APK**.
