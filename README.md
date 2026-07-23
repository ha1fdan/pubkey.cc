# pubkey.cc

Open-source, minimalist, end-to-end encrypted messaging built around public-key identity. No phone numbers, no personal identifiers, no metadata logging: identities and routing are anchored directly to public keys (`pubkey.cc/u/<key_or_handle>`).

The server is a blind relay: it routes opaque ciphertext envelopes by recipient pubkey and never sees plaintext or private key material.

## Structure

- `backend/`: Python/FastAPI WebSocket relay + Redis-backed ephemeral offline queue (TTL, no persistent retention).
- `frontend/`: Vanilla JS + Vite web client. Zero sign-up: click "Create Identity" to generate a keypair on-device, get a shareable link + QR code (`/u/<public_key>`), and start chatting. Contacts, nicknames, and message history live locally in IndexedDB, the server never sees any of it. Includes mutual safety-number verification, disappearing messages with a live countdown, a panic button that wipes everything on this device, and two ways to recover or move your identity: a passphrase-encrypted backup file, or a paper key (a short recovery code, the same one you'd use to add a new device to this account).

## Quickstart

```bash
docker compose up --build
```

This brings up Redis, the backend (`localhost:8000`), and a production build of the frontend served via nginx (`localhost:5173`).

For local development with hot reload, run the pieces natively instead:

```bash
# Redis
docker run --rm -p 6379:6379 redis:7-alpine

# Backend
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload

# Frontend (separate shell)
cd frontend
npm install
npm run dev
```

## Production

`docker-compose.prod.yml` pulls the images CI already built and published to GHCR instead of building locally, and requires real config (no `localhost` fallbacks):

```bash
cp .env.prod.example .env.prod   # fill in CORS_ORIGINS at minimum
docker compose -f docker-compose.prod.yml --env-file .env.prod pull
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d
```

See `CLAUDE.md` for details, including why `VITE_RELAY_WS_URL`/`VITE_RELAY_HTTP_URL` aren't set here (they're baked into the frontend image at CI build time).
