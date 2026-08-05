# Deploying AOS Hub to Cloudflare

The Cloudflare runtime serves the same shared `aos-hub-core` API, console, and
machine surfaces as the native Hub. Its relational system of record is the
`HubDb` Durable Object's colocated SQLite.

## Required repository-owned hardened-egress gateway

Cloudflare's Fetch API does not expose a connect-time DNS resolver/pinning hook.
The Hub Worker therefore refuses to fetch tenant- or administrator-controlled
origins directly. Deploy the `aos-hub-egress` binary behind an operator-owned
HTTPS name and pass its exact endpoint with `--hardened-egress-url`.

The adapter contract must:

The packaged gateway disables environment proxies and automatic redirects,
validates all DNS answers at connect time while retaining hostname SNI, rejects
non-global/unknown peers, revalidates each manual redirect, applies request,
response, redirect, and time caps, strips upstream internal headers, and signs
the v2 response evidence. Mutating requests cannot redirect; authenticated GET
redirects cannot change origin.

Generate one 32-byte hex key, assign a stable key id, store the key in an
owner-private gateway key file, start the gateway, and install `KEY_ID:KEY` as
the Worker's single atomic `HUB_EGRESS_SHARED_KEY` secret:

```sh
aos-hub-egress \
  --listen 127.0.0.1:8430 \
  --key-id 2026-08-a \
  --shared-key-file /run/secrets/aos-hub-egress.key \
  --nonce-database-url postgres://egress@db/aos_egress
```

Every gateway replica must use the same strongly-consistent nonce database.
Admission is an atomic primary-key insert committed before the upstream request
starts, so a nonce has one effect across replicas and process restarts. Use
PostgreSQL for replicated gateways. A file-backed SQLite URL is supported only
for a singleton process, where it still preserves admission across restarts.

Missing bindings or evidence fail startup/calls closed. Cloudflare platform
policy alone is not treated as SSRF protection.

## Installer flow

Use the hermetic `aos-hub-cloudflare` package. The installer provisions R2 and
KV, renders the service/Durable Object bindings, deploys the prebuilt Worker,
and installs runtime secrets. `HubDb` applies the shared schema on first use;
`worker install` bootstraps root through its seal-gated internal operation.

```sh
nix-build -A pkgs.aos-hub-cloudflare
HUB=./result/bin/aos-hub

export CLOUDFLARE_API_TOKEN=…
export HUB_CLOUDFLARE_API_TOKEN=… # scoped route-observation token
export HUB_HARDENED_EGRESS_URL=https://egress.example.com/v1/fetch
export HUB_EGRESS_SHARED_KEY=2026-08-a:… # same id/key already active on gateway

"$HUB" worker install \
  --name aos-hub \
  --hardened-egress-url "$HUB_HARDENED_EGRESS_URL" \
  --cloudflare-api-token "$HUB_CLOUDFLARE_API_TOKEN" \
  --domain reg.example.com \
  --root-email ops@example.com \
  --root-password-stdin
```

For rotation, add `--next-key-id` and `--next-shared-key-file` to every gateway
replica first. Deploy the Worker with the next `KEY_ID:KEY` only after the
authenticated challenge succeeds, then promote/remove the old gateway key.
The gateway accepts at most the current and next ids, so overlap is explicit
and bounded; the Worker secret changes atomically as one value.

`HUB_JWT_SECRET` and `HUB_SEAL_KEY` are minted when absent and printed once.
The egress key is never minted or recovered by the Worker installer: provision
it on the gateway first and provide it on every install, deploy, or rotation.
Before `wrangler deploy` or any secret write, the installer completes a fresh,
mutually authenticated `/v1/challenge`; a wrong, stale, or unavailable gateway
therefore leaves the existing Worker untouched. Domain-probe signer material is installed from an
owner-private, non-symlink file. The Worker also requires the
`HUB_DOMAIN_PROBE_SIGNER_MANIFEST` secret and `HUB_DNS_JSON_ENDPOINT` variable
when domain verification is enabled.

## Manual deployment

The checked-in `wrangler.toml` documents every required binding. Replace its R2,
KV, and `HUB_HARDENED_EGRESS_URL` placeholders, set the required secrets with
`wrangler secret put`, and deploy. `HubDb` initializes its schema on first use.

For upgrades, redeploy the new prebuilt artifact with the complete intended
custom-domain set. Schema upgrades remain owned by `HubDb` startup, and topology
resources must be changed through the typed Hub API rather than direct SQL.
