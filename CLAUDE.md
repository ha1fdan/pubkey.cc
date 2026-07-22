# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

pubkey.cc is an open-source, minimalist, end-to-end encrypted (E2EE) messaging platform built around public-key cryptography. Identities and routing endpoints are anchored directly to public keys (`pubkey.cc/u/<key_or_handle>`), with no phone numbers or personal identifiers. The server is an untrusted blind relay: it never sees plaintext or private key material.

## Commands

### Backend (`backend/`)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt   # setup
.venv/bin/uvicorn app.main:app --reload                                   # run dev server (needs Redis on REDIS_URL)
.venv/bin/pytest -q                                                       # run all tests
.venv/bin/pytest tests/test_auth.py::test_verify_challenge_signature_accepts_valid_signature  # run a single test
```

Tests run against `fakeredis` (see `tests/conftest.py`), so a real Redis instance is not required for the test suite, only for running the server itself.

### Frontend (`frontend/`)

```bash
npm install
npm run dev       # Vite dev server
npm run build     # production build
```

### Full stack

`docker compose up --build` brings up Redis, the backend, and a production build of the frontend (served via nginx on `localhost:5173`) together (see `docker-compose.yml`). The frontend image is a multi-stage build: `npm run build` in a `node:20-alpine` stage, then the static `dist/` is served by `nginx:alpine`.

Domain configuration is env-driven, not hardcoded, since the backend and frontend are typically deployed on different subdomains (e.g. `pubkey.cc` and `api.pubkey.cc`):

- `CORS_ORIGINS` (backend): comma-separated list of origins the relay accepts requests from (`config.CORS_ORIGINS`). Defaults to `http://localhost:5173` in `docker-compose.yml`.
- `VITE_RELAY_WS_URL` / `VITE_RELAY_HTTP_URL` (frontend): where the browser bundle points for the WebSocket relay and REST API. These are Vite build args, not container runtime env vars, since Vite inlines `VITE_*` values into the JS bundle at build time; setting them at `docker run` time does nothing after the fact. Defaults to `localhost:8000` in `docker-compose.yml`.

Copy `.env.example` to `.env` at the repo root to override any of these for `docker compose up` (compose reads `.env` automatically); see that file for a real-domain example. For iterating on the frontend, prefer `npm run dev` (hot reload) over rebuilding the container.

### CI/CD (`.github/workflows/docker-publish.yml`)

On every push to `main`/`develop`, a `v*.*.*` tag, or manual dispatch: a `test` job runs the backend pytest suite and a frontend `npm run build`, then (only if that passes) a `build-and-push` job builds both Docker images via a `[backend, frontend]` matrix and pushes them to GitHub Container Registry as `ghcr.io/<owner>/<repo>-backend` and `ghcr.io/<owner>/<repo>-frontend`, tagged by branch, git tag, short SHA, and `latest` (default branch only) via `docker/metadata-action`.

The frontend image build consumes two optional repo variables (`Settings -> Secrets and variables -> Actions -> Variables`, not secrets, they're public URLs): `VITE_RELAY_WS_URL` and `VITE_RELAY_HTTP_URL`. Unset, they fall back to the `localhost:8000` dev defaults, meaning a `latest` image pulled without configuring these will point at localhost, not your production API domain, since Vite bakes them into the JS bundle at build time and there's no way to change that after the image exists. Set them (e.g. `wss://api.pubkey.cc/ws` / `https://api.pubkey.cc`) before relying on the published image for a real deployment.

GHCR packages pushed via `GITHUB_TOKEN` are usually private by default on first push; make them public (or configure pull access) from the package's own settings on GitHub if they need to be pulled outside CI.

## Architecture

**Backend (`backend/app/`)**: FastAPI app with one WebSocket endpoint (`/ws`) and a small directory REST API:

- `auth.py`: Connection-ownership proof. On connect, the server sends a random nonce challenge; the client must sign it with its identity private key (ECDSA P-256) and the server verifies the signature against the client-supplied public key. Web Crypto's ECDSA output is raw fixed-width `r||s`, which `auth.py` converts to DER before verifying with the `cryptography` library.
- `relay.py`: `ConnectionManager` holds an in-memory map of connected pubkey → WebSocket. Incoming envelopes (`{to, ciphertext, nonce, ts}`) are delivered directly if the recipient is connected, otherwise buffered via `storage.enqueue_message`. The server only ever routes opaque ciphertext; it never inspects or logs message content.
- `storage.py`: Redis-backed state, three kinds:
  - `queue:<pubkey>`: a list of undelivered envelopes with a TTL (`MESSAGE_TTL_SECONDS`) refreshed on every push, drained atomically (read+delete in one pipeline) when the recipient reconnects. This one is genuinely ephemeral.
  - `directory:<pubkey_or_handle>`: public key bundle (`identity_pub`, `exchange_pub`) published via `POST /register` and resolved via `GET /u/<key_or_handle>`.
  - `recovery:<recovery_id>`: an opaque, passphrase-encrypted identity backup (the same shape `exportIdentityBackup()` produces client-side), stored via `PUT /recovery/<recovery_id>` and fetched via `GET /recovery/<recovery_id>`. `recovery_id` is a SHA-256 of the user's paper key (see `recoveryIdForPaperKey()` in `crypto.js`), so the server never sees the paper key itself, and possession of the unguessable id is the only access control, the same trust model as a secret URL.
- `main.py`: wires the FastAPI routes to the above; CORS origins come from `config.CORS_ORIGINS` (`CORS_ORIGINS` env var, comma-separated, defaults to `*` for local dev).

**Frontend (`frontend/src/`)**: no framework, just Vite + the Web Crypto API + IndexedDB, rendered with plain template-string DOM replacement and a `data-action` click/submit delegation pattern (see the `handlers` map and the two `app.addEventListener` calls at the bottom of `app.js`):

- `crypto.js`: key generation, message encryption, fingerprinting, and identity backup/restore. Two separate P-256 keypairs per user: an identity keypair (ECDSA, for signing the auth challenge) and an exchange keypair (ECDH, for deriving a shared AES-GCM key with a peer). P-256 is used for both because it's the one curve Web Crypto supports natively across all major browsers without flags. `fingerprint()` hashes a single public key for display; `safetyNumber()` hashes the sorted pair of both parties' identity keys so both sides compute the same value, an MVP stand-in for Signal-style SAS comparison. `exportIdentityBackup()`/`importIdentityBackup()` export both private keys as JWK and encrypt them with a passphrase-derived key (PBKDF2-SHA256, 250k iterations, AES-GCM); this is the shared primitive behind both recovery paths below. When reconstructing the public half of a keypair from a private JWK (to avoid a second export/import round trip), the JWK's `key_ops` field must be stripped before re-import: it reflects the *private* key's usages (e.g. `["sign"]`) and otherwise conflicts with the `["verify"]`/`[]` usages requested for the public half, and `importKey` rejects the mismatch. `generatePaperKey()`/`recoveryIdForPaperKey()` implement the paper-key recovery scheme: a random ~121-bit code (not user-chosen, see below) doubles as the `exportIdentityBackup` passphrase, and its SHA-256 doubles as the lookup id for where the resulting encrypted blob lives server-side (`PUT`/`GET /recovery/<id>`). **This is ECDH + AES-GCM, not a full Double Ratchet**: sessions aren't forward-secret. Upgrading to a proper ratchet is tracked as follow-up work, not yet implemented.
- `db.js`: IndexedDB wrapper, the local-first store: `identity` (the CryptoKeyPairs themselves, IndexedDB's structured clone supports storing `CryptoKey` directly, so there's no export/import round-trip for your own keys on every page load), `contacts` (identityPub, exchangePub, nickname, fingerprint), and `messages` (decrypted plaintext, keyed by an autoincrement id with a `byPeer` index). All of this is local-only; the server never sees it. `wipeAll()` powers the panic button.
- `router.js`: a minimal client-side router (`pushState`/`popstate` + `data-link` click interception) for `/u/<key_or_handle>` share links.
- `ws.js`: `connectRelay()` handles the auth challenge/response handshake transparently, then exposes `send(envelope)` for already-encrypted messages and an `onMessage` callback for incoming ones.
- `app.js`: the app: onboarding (create a new identity, restore one from an encrypted backup file, or restore via paper key, all three converge on `finishIdentitySetup()`, which persists to IndexedDB, registers with the backend, and connects to the relay), the chat shell (sidebar of contacts, conversation view, composer with a disappearing-message TTL selector), the share modal (QR code via the `qrcode` package), the backup modal (passphrase-protected identity export, downloaded as a `.json` file via a Blob URL), the paper key modal (generates a code, requires an explicit "I've saved this" click before it's uploaded to `/recovery/<id>`, so opening the modal alone doesn't silently write anything), the verify modal (mutual safety number + nickname), and the panic-wipe confirmation. Disappearing-message expiry (`expiresAt`) is encrypted *inside* the message payload (`{text, expiresAt}` is what actually gets AES-GCM'd) rather than sent as relay metadata, so the server never learns which messages are ephemeral. The countdown next to each disappearing message ticks live: `startExpirySweep()`'s 1s interval either does a full `render()` (when a message actually expires and needs removing from state/IndexedDB) or, on every other tick, calls `tickExpiryCountdowns()` to patch just the `.expiry[data-expires-at]` text nodes directly, this avoids re-rendering (and re-scrolling) the whole conversation every second just to count down a number. Visiting `/u/<key>` for a key that isn't already a contact triggers a live `GET /u/<key>` lookup and shows an add-contact banner; receiving a message from an unknown sender does the same lookup automatically and silently adds them.
- `nginx.conf`: SPA fallback (`try_files $uri /index.html`) for the production Docker image. Without it, direct navigation to `/u/<key>` 404s at the nginx layer before the client-side router ever runs (`npm run dev`'s Vite dev server doesn't have this problem, it falls back to `index.html` for unknown paths by default).

## Security model notes for future work

- The identity key *is* the account. There's no separate signup/login; recovery across devices/browsers is either a passphrase-encrypted backup file or a paper key (see `exportIdentityBackup`/`importIdentityBackup`/`generatePaperKey` in `crypto.js`); if you have none of local IndexedDB, a backup file, or a saved paper key, the identity is gone. Panic/Clear Session wipes it irrecoverably. Both recovery paths are opt-in via sidebar buttons, not forced during onboarding, worth revisiting before shipping this beyond a demo.
- The paper key is intentionally server-generated random, not user-chosen, specifically so its ~121 bits of entropy resists brute-forcing the recovery blob; a user-chosen passphrase would reintroduce that risk for the "paper key" path the same way it already exists (by user choice) for the file-backup path.
- "Add a new device" and "recover a lost device" are the same operation here (entering a paper key restores the same identity keys onto whatever device you type it into); there's no independent per-device key material or multi-device fan-out at the relay level. That's a materially different, larger feature (each linked device would need its own keys and the relay would need to deliver to all of a recipient's active connections) and isn't implemented.
- The exchange key exposed via `/u/<key_or_handle>` is long-lived in the current MVP; real forward secrecy requires rotating/ephemeral pre-keys (X3DH/Double Ratchet-style), which is not yet implemented.
- The directory (`storage.publish_directory_entry`) and recovery blobs (`storage.save_recovery_blob`) have no TTL and no proof of exclusive ownership beyond "whoever writes first (or knows the id) wins", no protection against overwrite/squatting yet.
- `safetyNumber()` is a single SHA-256 over the two raw identity keys, not Signal's iterated-hash fingerprint algorithm, fine as an MVP MITM check, not audited.
