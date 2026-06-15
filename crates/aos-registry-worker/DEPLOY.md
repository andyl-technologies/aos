# Deploying the AOS registry Worker to Cloudflare

The `aos-registry-worker` is the **read-path** target of the RFC-0004 registry
hub: an R2-backed machine facade (dumb-HTTP git origin + Nix binary cache), a
D1-backed browse UI + JSON read API, and a Cron-triggered indexer. It has **no
write/publish path, no console, and no authentication** — it serves `public`
registries anonymously. The write path, producer console, and IAM live in the
native `aos-registry-hub` binary.

Because the Worker is read-only, a new deployment is **seeded entirely through
`wrangler`** against your Cloudflare account. There is no human "root user" on
the Worker; the two roots are:

1. **The registry's trust anchor** — the `trust_keys` you put in the D1
   `registries` row (an Ed25519 roster, the `keys.toml` lines). The Cron indexer
   only admits surface bytes that verify against it. The matching **private key
   never leaves the developer's machine**.
2. **Whoever runs `wrangler`** against your account — the operational root that
   provisions D1/R2/KV, seeds D1, and uploads R2.

`wrangler` is packaged hermetically by AOS: `nix run .#miniflare -- wrangler …`
exposes the pinned `wrangler` (or use `pkgs.miniflare`'s `bin/wrangler` on
`PATH`). Every command below can be run through it.

## 0. Prerequisites

- A Cloudflare account (D1, R2, KV, and Cron Triggers are available on the
  Workers Paid plan).
- Authentication — interactive once:
  ```sh
  wrangler login                      # OAuth, or:
  export CLOUDFLARE_API_TOKEN=…       # token with Workers/D1/R2/KV edit scopes
  ```
- A built **registry surface** to serve — the signed git-object layout the
  facade exposes (`HEAD`, `info/refs`, `keys.toml`, `channels/<chan>/<bucket>`,
  loose `objects/…`, `<hash>.narinfo`, `nar/…`). This is what `apr release
  --upload-url <hub>` produces, or, for a smoke test, the fixture from
  `cargo run -p aos-registry-worker --example gen_surface -- <out-dir>`.

## 1. Provision the bound resources

```sh
wrangler d1 create aos-registry-hub
wrangler r2 bucket create aos-registry-surfaces
wrangler kv namespace create SESSIONS
```

Paste the returned `database_id` and KV `id` into `wrangler.toml` (they replace
the all-zero placeholders). The binding **names** (`REGISTRY_DB`,
`REGISTRY_BUCKET`, `SESSIONS`) must not change — they match
`handlers::bindings`.

## 2. Apply the D1 schema

```sh
wrangler d1 execute aos-registry-hub --remote \
  --file crates/aos-registry-worker/migrations/0001_schema.sql
```

## 3. Seed the registry row — the trust-anchor bootstrap

This is the one piece of control-plane state the Worker cannot derive: which
registries exist, their R2 `prefix`, visibility, and **trust roster**. Insert it
directly (the Worker has no admin API):

```sh
wrangler d1 execute aos-registry-hub --remote --command \
"INSERT INTO registries
   (slug, source_url, trust_keys, require_signatures, created_at, visibility, prefix)
 VALUES
   ('demo',
    'r2://aos-registry-surfaces/demo',
    '[\"maintainer:Ed25519:AAAAC3NzaC1lZDI1NTE5...\"]',
    1, unixepoch(), 'public', 'demo');"
```

- `trust_keys` is a **JSON array** of `keys.toml` roster lines
  (`<id>:Ed25519:<base64>`). This is the cryptographic root of trust; the
  indexer rejects any surface whose signed `keys.toml`/commits/tags do not
  verify against it.
- `prefix` is the registry's key prefix within the shared bucket (R2 key =
  `<prefix>/<machine-path>`).
- `require_signatures = 1` keeps the indexer fail-closed.

## 4. Upload the signed surface to R2

The R2 key for any object is `<prefix>/<surface-relative-path>`:

```sh
( cd surface && find . -type f -print0 ) | while IFS= read -r -d '' f; do
  rel=${f#./}
  wrangler r2 object put "aos-registry-surfaces/demo/$rel" --file "surface/$rel" --remote
done
```

(For a real registry this is large; in production the surface is pushed by the
publish path, not hand-uploaded. The `deploy/cf-seed.sh` helper wraps steps
2–4.)

## 5. Deploy the Worker

```sh
wrangler deploy
```

`wrangler` runs the `[build]` command (`worker-build --release`), uploads the
wasm + JS shim, binds D1/R2/KV, and installs the `*/15 * * * *` Cron trigger.

> Hermetic alternative to `worker-build`: `nix build .#aos-registry-worker-dist`
> produces `shim.mjs` + `index.wasm` from AOS tools only (no network). Point
> `wrangler deploy --no-bundle` at that output, or set `main` to the built shim.

## 6. Index

The Cron trigger fires the `scheduled` handler every 15 minutes; it walks each
`public` registry's R2 surface and (re)builds `packages`/`channels`/`releases`
in D1, verifying every signature against `trust_keys` and enforcing the
per-channel anti-rollback floor. To populate D1 immediately instead of waiting:

```sh
# local dry-run against the same bindings:
wrangler dev --test-scheduled         # then: curl 'http://localhost:8787/__scheduled'
# or trigger the deployed Worker's scheduled event from the Cloudflare dashboard.
```

After indexing, the Worker serves:

- `https://aos-registry-hub.<subdomain>.workers.dev/demo/` — browse UI
- `…/demo/-/packages?q=…` — JSON read API
- `…/demo/nix-cache-info`, `…/demo/<hash>.narinfo`, `…/demo/nar/…` — Nix cache
- `…/demo/info/refs?service=git-upload-pack` — dumb-HTTP git origin

## What this deployment is *not*

No write/publish, no producer console, no auth/SSO/device-flow, no
private-registry access control — those are native-hub features. Run the native
`aos-registry-hub` for human accounts, an instance admin (`iam.admin` at the
root scope), publishing, and config management; the Worker is the read-path edge
cache of registries that already exist. See `README.md` for the full deferred
list.
