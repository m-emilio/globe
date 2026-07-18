# Multiplayer Globe App

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cloudflare/templates/tree/main/multiplayer-globe-template)

![Multiplayer Globe Template Preview](https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/43100bd9-8e11-4c20-cc00-3bec86253f00/public)

<!-- dash-content-start -->

Using the power of [Durable Objects](https://developers.cloudflare.com/durable-objects/), this example shows website visitor locations in real-time. Anyone around the world visiting the [demo website](https://multiplayer-globe-template.templates.workers.dev) will be displayed as a dot on the globe! This template is powered by [PartyKit](https://www.partykit.io/).

## How It Works

Each time someone visits the page, a WebSocket connection is opened with a Durable Object that manages the state of the globe. Visitors are placed on the globe based on the geographic location of their IP address, which is exposed as a [property on the initial HTTP request](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties) that establishes the WebSocket connection.

The Durable Object instance that manages the state of the globe runs in one location, and handles all incoming WebSocket connections. When a new connection is established, the Durable Object broadcasts the location of the new visitor to all other active visitors, and the client adds the new visitor to the globe visualization. When someone leaves the page and their connection is closed, the Durable Object similarly broadcasts their removal. The Durable Object instance remains active as long as there is at least one open connection. If all open connections are closed, the Durable Object instance is purged from memory and remains inactive until a new visitor lands on the page, opens a connection, and restarts the lifecycle.

## More on Durable Objects

In this template, only one Durable Object instance is created, since all visitors should see updates from all other visitors, everywhere in the world. A more complex version of this application could instead show a map of the country the visitor is located in, and only display markers for other visitors who are located in the same country. In this case, a Durable Object instance would be created for each country, and the client would connect to and receive updates from the Durable Object instance corresponding to the visitor's country.

For this example, Durable Objects are used for synchronizing but not storing state. Since visitor connections are ephemeral, and tied to the in-memory lifespan of the Durable Object instance, there's no need to use persistent storage. However, a more complex version of this application could display the all-time visitor count, which needs to be persisted beyond the in-memory lifespan of the Durable Object. In this case, the Durable Object code would use the [Durable Object Storage API](https://developers.cloudflare.com/durable-objects/api/storage-api/) to persist the value of the counter.

<!-- dash-content-end -->

## Getting Started

Outside of this repo, you can start a new project with this template using [C3](https://developers.cloudflare.com/pages/get-started/c3/) (the `create-cloudflare` CLI):

```
npm create cloudflare@latest -- --template=cloudflare/templates/multiplayer-globe-template
```

A live public deployment of this template is available at [https://multiplayer-globe-template.templates.workers.dev](https://multiplayer-globe-template.templates.workers.dev)

## Setup Steps

1. Install the project dependencies with a package manager of your choice:
   ```bash
   npm install
   ```
2. Copy env template and fill secrets:
   ```bash
   cp .dev.vars.example .dev.vars
   ```
3. Local dev:
   ```bash
   npm run dev
   ```
4. Deploy the project
   ```bash
   npx wrangler deploy
   ```
5. And monitor your workers!
   ```bash
   npx wrangler tail
   ```

## Auth + Local Transit (OpenPGP)

Local Transit requires a **PGP-authenticated session**. No Stripe MCP or payment is required by default.

### How auth works

1. **Register** — browser generates a keypair **client-side**. Private key is downloaded then **wiped from app memory**. Only the **public** key is sent to `POST /api/auth/register`.
2. Worker stores fingerprint + public key and returns a **session token** (opaque server id) + HttpOnly cookie. This token is **not** a PGP private key.
3. **Sign in** — challenge–response: private key signs locally (file/paste, memory only) → `POST /api/auth/login` with signature only → private key wiped → session token issued.
4. **API auth** accepts (in order): `Authorization: Bearer <sessionToken>`, `x-session-token`, cookie, or `?auth_token=` / `?session_token=`. URL tokens are adopted via `POST /api/auth/adopt-token` and stripped from the address bar.
5. `GET /api/transit-nearby` returns **401** until a valid session is present.

**Private keys** never leave the client and are never stored by the app. **Session tokens** are short-ish-lived server credentials for API access after PGP auth.

**Key loss = account loss.** Back up your private key offline.

Optional paid gate (later): set `TRANSIT_REQUIRE_PAYMENT=1` and use Stripe webhook/claim to set `user.transitPaid`.

### Cloudflare KV

| Binding      | Production ID                      | Preview ID                         |
|--------------|------------------------------------|------------------------------------|
| `BILLING_KV` | `351eb0e39a014fb3912e709d85a4a445` | `25476e1f195246afb1bc8cee3d9f8ba8` |

Used for users, sessions, challenges, and optional payment records.

### Auth API

| Route | Purpose |
|-------|---------|
| `POST /api/auth/register` | `{ publicKeyArmored }` → user + `sessionToken` |
| `POST /api/auth/challenge` | `{ fingerprint }` → one-time message to sign |
| `POST /api/auth/login` | `{ fingerprint, challengeId, signatureArmored }` → user + `sessionToken` |
| `POST /api/auth/adopt-token` | `{ sessionToken }` → set cookie (URL handoff) |
| `POST /api/auth/logout` | Clear session |
| `GET /api/auth/me` | Current user + `sessionToken` echo |

### Optional Stripe (hardened, not required)

Payment Link `client_reference_id` is forced to the **logged-in user id** (not client-supplied). Claim only unlocks when that id matches. Payment-status is read-only (no rebinding). Webhook still requires signature verification.

```bash
# only if enabling payment later
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put STRIPE_WEBHOOK_SECRET
npx wrangler secret put TRANSIT_PUBLICAPI_V4
```
