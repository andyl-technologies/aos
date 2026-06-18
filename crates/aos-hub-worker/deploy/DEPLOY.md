# Deploying the AOS registry hub to Cloudflare

The registry hub ships in two runtimes from one codebase (RFC-0004 Phase 5): a
native `aos-hub` server and the `aos-hub-worker` Cloudflare Worker
(`wasm32-unknown-unknown`). Both serve the *same* shared `aos-hub-core`
surface — RPC, the R2 machine-path facade, the no-JS browse UI, auth/console,
and the write path — so a Cloudflare deployment is full-featured, not a read-only
mirror.

This guide covers standing up and maintaining a Cloudflare deployment.

## The installer (recommended)

The native hub binary is also the deployment **installer**: a wasm Worker can't
shell `wrangler`, read your credentials, or touch the filesystem, so the
install/maintenance tooling is native and the compiled Worker (`shim.mjs` +
`index.wasm`) is the *payload* it deploys. The `aos-hub-cloudflare` Nix
package bundles `wrangler`, `node`, and the prebuilt Worker wasm into one
self-contained closure.

Deployment is **two concerns, cleanly split**:

- **`worker deploy`** — the provider-specific part only: provision the provider
  resources and deploy the Worker artifact + secrets. Nothing touches the
  database.
- **`init`** — provider-neutral schema migration + root bootstrap, run by *you*
  over D1 (`--target d1:<name>`). **There is no public init endpoint** — the
  schema is applied by the authenticated operator's CLI, never over HTTP.

```sh
# Build the installer (one self-contained closure: hub + wrangler + node + wasm).
nix-build -A pkgs.aos-hub-cloudflare
HUB=./result/bin/aos-hub

# Authenticate with the provider — EITHER option works:
#   (a) API token: export CLOUDFLARE_API_TOKEN=… (Workers/D1/R2/KV + Account:Read)
#   (b) browser OAuth, once: "$HUB" worker login
# Check it with: "$HUB" worker whoami   (clear it with: "$HUB" worker logout)
export CLOUDFLARE_API_TOKEN=…

# 1. Provider: provision D1/R2/KV, deploy the wasm, set the runtime secrets.
"$HUB" worker deploy \
  --provider cloudflare \
  --name aos-hub \
  --external-url https://reg.example.com \
  --custom-domain reg.example.com        # optional; binds a custom domain

# 2. Database: migrate the schema and bootstrap the root admin, over D1.
"$HUB" init --target d1:aos-hub \
  --root-email ops@example.com --root-password-stdin <<<"$ROOT_PASSWORD"
```

`worker deploy` runs, in order:

1. **provision** — `wrangler d1 create` / `r2 bucket create` / `kv namespace
   create` (idempotent; an existing resource is skipped), then reads the D1/KV
   ids back from `wrangler … list`.
2. **deploy** — renders a `wrangler.toml` over the bundled wasm dist (no
   `[build]` command — the hermetic dist is deployed as-is) and `wrangler
   deploy`s it.
3. **secrets** — `wrangler secret put` for the runtime secrets (piped on stdin,
   never on argv). `HUB_JWT_SECRET` and `HUB_SEAL_KEY` are **minted randomly**
   when not supplied and printed once — record them.

`init --target d1:<name>` then applies the shared `aos_hub_core` migrations
over D1 (via the bundled `wrangler d1 execute`) and, when `--root-email` is set,
creates the root admin — the same `Database` code the native hub runs locally.

**Custom domains.** `--custom-domain aos.example.org` emits a `custom_domain`
route, and `wrangler deploy` provisions the domain (DNS record + TLS cert) on
first deploy — **provided the domain's zone (`example.org`) is already a zone on
the same Cloudflare account**. Set `--external-url` to the same `https://…` URL so
`HUB_EXTERNAL_URL` matches. Without `--custom-domain` the Worker serves only on
`https://<name>.<subdomain>.workers.dev`.

**One-shot convenience:** `"$HUB" worker install --provider cloudflare
--external-url … --root-email … --root-password-stdin` composes `worker deploy`
then `init --target d1:<name>` in a single command.

### Authentication (two options)

Provider auth is a `worker` concern (each provider has its own); for Cloudflare:

- **API token** — `export CLOUDFLARE_API_TOKEN=…` (a token with Workers / D1 /
  R2 / KV edit + Account Settings read). Best for CI and remote/headless hosts.
- **Browser OAuth** — `"$HUB" worker login` opens your browser to authorize and
  stores the credentials; `worker deploy`/`init` then use them automatically.
  `"$HUB" worker whoami` shows the current identity; `"$HUB" worker logout`
  clears it.

The deploy/migrate commands accept **either** transparently. Tokens are never
passed on argv; the installer doesn't handle credentials itself.

> **OAuth over SSH (remote builder):** `worker login` runs a callback on
> `localhost:8976` of the host it runs on. When you run it on a remote builder
> over SSH, forward that port so your local browser's redirect reaches it:
> `ssh -L 8976:localhost:8976 dylan@builder …`, then run `"$HUB" worker login`
> and open the printed URL in your local browser. (A token via
> `CLOUDFLARE_API_TOKEN` avoids the port-forward entirely.)

### Runtime configuration

The Worker reads these (set by `worker deploy`):

| Variable | Kind | Required | Meaning |
|---|---|---|---|
| `HUB_JWT_SECRET` | secret | yes | HS256 JWT signing key (minted if omitted) |
| `HUB_SEAL_KEY` | secret | yes | at-rest AES-GCM sealing key for OIDC client secrets (minted if omitted) |
| `HUB_EXTERNAL_URL` | var | yes | the hub's externally-reachable base URL |
| `HUB_EMAIL_API_URL` | var | no | magic-link email relay endpoint (unset → links are logged) |
| `HUB_EMAIL_API_TOKEN` | secret | no | bearer token for the email relay |

The root admin is **not** a Worker secret — it is created by `init`/`reset-root`
directly in D1. `wrangler` reads `CLOUDFLARE_API_TOKEN` (or an OAuth login) from
the environment; the installer never handles your Cloudflare credentials itself.

## Maintenance

Every `aos-hub` admin command takes a global `--target`, so the *same*
command tree runs against either deployment backend:

```text
--target local            the native sqlite file under --root (default)
--target d1:<name>        a live Cloudflare D1 database (via bundled wrangler)
--target d1-local:<name>  the local miniflare D1 engine (for testing)
```

For example `aos-hub org add acme "Acme" --target d1:aos-hub`
runs `create_org` against live D1 with the identical code path the native hub
uses locally. Commands that store sealed secrets (`idp`, `hosted-key`,
`channel`) need the deployment's seal key for a non-local target — pass
`--seal-key` or set `HUB_SEAL_KEY` (the same value used at deploy) so the secrets
round-trip. A few commands that operate on the local filesystem (`org export`,
`validate repair`) are local-only and reject a non-local `--target`.

- **Update the deployed Worker** (after a new build):
  ```sh
  "$HUB" worker deploy --name aos-hub --external-url https://reg.example.com
  ```
- **Reset (or create) the root password** — runs the *same* `Database`
  user/password code the native `user set-password` runs, over the chosen
  backend (the unification seam: one CLI, either backend):
  ```sh
  "$HUB" reset-root --target d1:aos-hub --email ops@example.com --password-stdin <<<"$NEW_PASSWORD"
  ```
- **Re-run migrations** after a schema change ships:
  ```sh
  "$HUB" init --target d1:aos-hub
  ```
- **Seed a registry + its signed surface** — see `deploy/cf-seed.sh`:
  ```sh
  deploy/cf-seed.sh --slug demo --surface ./surface \
    --trust-key 'maintainer:Ed25519:AAAA…' --wrangler "$HUB_WRANGLER"
  ```
  The `*/15` Cron then verifies the R2 surface and populates
  `releases`/`channels` into D1.
- **Manage a hosted binary cache** — the `cache` command tree (create, list,
  show, update, rm, link/unlink, gc-policy, pin/renew/unpin, search, info,
  closure, gc-runs) runs against either backend via `--target`, the same as the
  rest of the admin tree:
  ```sh
  "$HUB" cache create acme-cache --org acme --binding primary \
    --visibility public --target d1:aos-hub
  "$HUB" cache link acme-cache acme/infra/prod/cdn --roots-packages \
    --target d1:aos-hub          # pin GC roots to the registry's packages
  ```
  `cache gc` is **local-only** (it sweeps NAR/narinfo bytes off the surface, so
  it needs filesystem access — like `org export` and `validate repair`); run it
  against the native `--target local` deployment or trigger it on the Worker via
  its scheduled Cron. Cache uploads count toward the owning org's quota, and
  `/metrics` exposes `aos_hub_cache*` gauges + GC counters for scraping.

## Manual `wrangler` path (no installer)

If you are not using the Nix installer, deploy by hand from the crate:

```sh
cargo install worker-build wrangler        # one-time tooling
wrangler d1 create aos-hub        # copy database_id into wrangler.toml
wrangler r2 bucket create aos-registry-surfaces
wrangler kv namespace create SESSIONS      # copy id into wrangler.toml
wrangler secret put HUB_JWT_SECRET
wrangler secret put HUB_SEAL_KEY
wrangler deploy                            # [build] runs worker-build to compile the wasm
# Apply the schema over D1 (no public init endpoint):
#   wrangler d1 execute aos-hub --remote --command "$(aos-hub schema dump | jq -r '.[]|. + ";"')"
# or, with the installer available: aos-hub init --target d1:aos-hub
```

The schema is applied over D1 by the operator — there is no `GET /_init`
endpoint. `aos-hub schema dump` prints the canonical `MIGRATIONS`
statements (the single source of truth), and `init --target d1:<name>` applies
them; there is intentionally no separate `wrangler d1 migrations` step.

## Validation boundary

The installer's pure logic (argv construction, `wrangler.toml` rendering,
`wrangler … list` id parsing, SQL-literal inlining, `--json` result parsing,
`schema dump`) is unit-tested, and `init`/`reset-root`/admin commands are
validated end-to-end against the local miniflare D1 engine (`--target
d1-local:<name>`), as is the deployed Worker under workerd + miniflare (migrated
from `schema dump`). The live `--remote` `wrangler` calls require a real
Cloudflare account and are validated operator-side — the same boundary the
Worker runtime tests draw at needing a workerd host.
