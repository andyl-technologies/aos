# AOS Hub Worker

`aos-hub-worker` is the Cloudflare shell for the shared `aos-hub-core`
application. It serves the same Connect API, producer console, authentication,
machine surfaces, topology controllers, and write path as the native Hub.

Platform-specific adapters provide:

- `HubDb`, a Durable Object with colocated SQLite, as the relational system of
  record;
- R2 for registry/cache surface objects;
- KV for cache-aside session state and revocation tombstones;
- Durable Objects/Queues for coordination and deferred work;
- edge rate-limit bindings; and
- Worker Fetch for external HTTP operations, with an optional authenticated
  `aos-hub-egress` router for installations requiring pinned DNS and signed
  connected-peer evidence.

`HubDb` applies the shared schema on first use, and administrative mutations
use the typed Hub API.

Webhook work is anchored in `HubDb`, not in Queue messages. Each message carries
only a stable delivery ID; the consumer conditionally leases that row with a
fencing token before resolving its secret version and sending. Cron both
materializes topology outbox events and drains a bounded due batch, so it is a
durable backstop for failed Queue publication. Delivery is at least once and
receivers should deduplicate retries by `X-AOS-Delivery-ID`.

## Outbound security boundary

Worker Fetch is the default outbound transport and needs no separately deployed
service. AOS validates targets, rebuilds a closed request, bounds redirects, and
prevents credentials from crossing origins. The optional packaged
`aos-hub-egress` router adds connect-time DNS pinning and signs its final-URL,
peer, status, and nonce evidence under `aos-hardened-egress-v3`. Missing, stale,
or invalid evidence fails closed whenever that transport is selected.
See [`deploy/DEPLOY.md`](deploy/DEPLOY.md).

## Build and deploy

Production deployment uses the hermetically built Worker artifact packaged with
`aos-hub-cloudflare`; the installer renders `wrangler.toml` and deploys it
without a host rebuild. The checked-in `wrangler.toml` exists for manual
development and documents required binding names.

```sh
nix build .#pkg-aos-hub-cloudflare
./result/bin/aos-hub worker install \
  --name aos-hub \
  --cloudflare-api-token "$HUB_CLOUDFLARE_API_TOKEN" \
  --domain reg.example.com \
  --root-email ops@example.com \
  --root-password-stdin
```

The Worker feature is target-gated so native workspace checks do not compile
Workers-only bindings. Runtime validation additionally requires workerd or a
Cloudflare account; database and shared-domain behavior is exercised through
the runtime-neutral core tests.

The canonical user guide is [Deploy AOS Hub to
Cloudflare](../../docs/users/aos-hub/cloudflare.md). It covers the supported
installer, provider resources, secrets, domains, updates, email, and
observability.

This crate's checked-in `wrangler.toml` is an implementation fixture. The
packaged installer generates deployment configuration from the current command
options and bundled Worker artifact; it is the supported operational path.
