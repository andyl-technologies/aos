# Deploying the AOS registry hub to Cloudflare

The registry hub ships in two runtimes from one codebase (RFC-0004 Phase 5): a
native `aos-registry-hub` server and the `aos-registry-worker` Cloudflare Worker
(`wasm32-unknown-unknown`). Both serve the *same* shared `aos-registry-core`
surface — RPC, the R2 machine-path facade, the no-JS browse UI, auth/console,
and the write path — so a Cloudflare deployment is full-featured, not a read-only
mirror.

This guide covers standing up and maintaining a Cloudflare deployment.

## The installer (recommended)

The native hub binary is also the deployment **installer**: a wasm Worker can't
shell `wrangler`, read your credentials, or touch the filesystem, so the
install/maintenance tooling is native and the compiled Worker (`shim.mjs` +
`index.wasm`) is the *payload* it deploys. The `aos-registry-hub-cloudflare` Nix
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
nix-build -A pkgs.aos-registry-hub-cloudflare
HUB=./result/bin/aos-registry-hub

# Authenticate wrangler with your Cloudflare account (either works):
export CLOUDFLARE_API_TOKEN=…            # an API token with Workers/D1/R2/KV scopes
#   …or run an interactive OAuth login once: `wrangler login`

# 1. Provider: provision D1/R2/KV, deploy the wasm, set the runtime secrets.
"$HUB" worker deploy \
  --provider cloudflare \
  --name aos-registry-hub \
  --external-url https://reg.example.com

# 2. Database: migrate the schema and bootstrap the root admin, over D1.
"$HUB" init --target d1:aos-registry-hub \
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

`init --target d1:<name>` then applies the shared `aos_registry_core` migrations
over D1 (via the bundled `wrangler d1 execute`) and, when `--root-email` is set,
creates the root admin — the same `Database` code the native hub runs locally.

**One-shot convenience:** `"$HUB" worker install --provider cloudflare
--external-url … --root-email … --root-password-stdin` composes `worker deploy`
then `init --target d1:<name>` in a single command.

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

Every `aos-registry-hub` admin command takes a global `--target`, so the *same*
command tree runs against either deployment backend:

```text
--target local            the native sqlite file under --root (default)
--target d1:<name>        a live Cloudflare D1 database (via bundled wrangler)
--target d1-local:<name>  the local miniflare D1 engine (for testing)
```

For example `aos-registry-hub org add acme "Acme" --target d1:aos-registry-hub`
runs `create_org` against live D1 with the identical code path the native hub
uses locally. Commands that store sealed secrets (`idp`, `hosted-key`,
`channel`) need the deployment's seal key for a non-local target — pass
`--seal-key` or set `HUB_SEAL_KEY` (the same value used at deploy) so the secrets
round-trip. A few commands that operate on the local filesystem (`org export`,
`validate repair`) are local-only and reject a non-local `--target`.

- **Update the deployed Worker** (after a new build):
  ```sh
  "$HUB" worker deploy --name aos-registry-hub --external-url https://reg.example.com
  ```
- **Reset (or create) the root password** — runs the *same* `Database`
  user/password code the native `user set-password` runs, over the chosen
  backend (the unification seam: one CLI, either backend):
  ```sh
  "$HUB" reset-root --target d1:aos-registry-hub --email ops@example.com --password-stdin <<<"$NEW_PASSWORD"
  ```
- **Re-run migrations** after a schema change ships:
  ```sh
  "$HUB" init --target d1:aos-registry-hub
  ```
- **Seed a registry + its signed surface** — see `deploy/cf-seed.sh`:
  ```sh
  deploy/cf-seed.sh --slug demo --surface ./surface \
    --trust-key 'maintainer:Ed25519:AAAA…' --wrangler "$HUB_WRANGLER"
  ```
  The `*/15` Cron then verifies the R2 surface and populates
  `releases`/`channels` into D1.

## Manual `wrangler` path (no installer)

If you are not using the Nix installer, deploy by hand from the crate:

```sh
cargo install worker-build wrangler        # one-time tooling
wrangler d1 create aos-registry-hub        # copy database_id into wrangler.toml
wrangler r2 bucket create aos-registry-surfaces
wrangler kv namespace create SESSIONS      # copy id into wrangler.toml
wrangler secret put HUB_JWT_SECRET
wrangler secret put HUB_SEAL_KEY
wrangler deploy                            # [build] runs worker-build to compile the wasm
# Apply the schema over D1 (no public init endpoint):
#   wrangler d1 execute aos-registry-hub --remote --command "$(aos-registry-hub schema dump | jq -r '.[]|. + ";"')"
# or, with the installer available: aos-registry-hub init --target d1:aos-registry-hub
```

The schema is applied over D1 by the operator — there is no `GET /_init`
endpoint. `aos-registry-hub schema dump` prints the canonical `MIGRATIONS`
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
