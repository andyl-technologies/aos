# Deploy AOS Hub to Cloudflare

The Cloudflare deployment runs the shared Hub request surface in a Worker. Its
system of record is SQLite inside a `HubDb` Durable Object; registry and cache
bytes live in R2, KV caches session and hot-key state, and a Cloudflare Queue
drains deferred post-write jobs. Outbound HTTPS uses Cloudflare's Worker Fetch
transport, so a complete deployment requires no VM, metal host, or separately
operated egress service. The schema migrates on first use.

Use the packaged installer. It contains the `aos-hub` deployment command,
Worker artifact, and AOS-built provider tooling.

## Install the Worker

Build the installer:

```sh
nix build .#pkg-aos-hub-cloudflare
```

Authenticate either by setting `CLOUDFLARE_API_TOKEN` in the environment or by
running the browser login:

```sh
./result/bin/aos-hub worker login
./result/bin/aos-hub worker whoami
```

The token must be able to deploy Workers and manage R2 and KV resources in the
account. A custom domain also requires access to its DNS zone.

The Worker needs a separate scoped token at runtime to observe route-control
state. Set it before the first install even when Wrangler uses browser login:

```sh
export HUB_CLOUDFLARE_API_TOKEN='scoped-runtime-token'
```

For a first deployment with a custom domain:

```sh
printf '%s\n' "$ROOT_PASSWORD" | \
  ./result/bin/aos-hub worker install \
    --name aos-hub \
    --domain hub.example.com \
    --root-email ops@example.com \
    --root-password-stdin
```

The domain's DNS zone must already belong to the same Cloudflare account. The
installer provisions resources, deploys the Worker, applies secrets, binds the
domain, and bootstraps the instance owner.

Without `--domain`, the Worker remains available at its `workers.dev` address.
The installer prints a follow-up `worker bootstrap-root` command template.
Replace its placeholder with the deployed URL reported by Wrangler, provide the
printed seal key through `HUB_SEAL_KEY`, and supply the root password again with
`--password-stdin`. The complete form appears under "Update the deployment."

## Know what the installer creates

| Resource | Purpose |
| --- | --- |
| `HubDb` Durable Object | Transactional SQLite system of record and short internal SQL operations |
| Control/tenant/registry/cache Durable Objects | Resource-affine request execution; no copied relational state |
| R2 bucket | Registry and binary-cache surfaces |
| KV namespace | Read-through cache for sessions, revocations, and hot point state |
| Queue | Deferred post-write propagation and delivery jobs |
| Coordinator Durable Object | Publish lease coordination |
| Rate-limit bindings | Edge request budgets |
| Scheduled trigger | Fifteen-minute maintenance and indexing backstop |
| Worker assets | Web interface static files |

The generated Worker configuration grants maintenance and Queue invocations
up to five minutes of CPU time and 100,000 subrequests. Full registry indexing
verifies the signed object graph and can exceed Cloudflare's conservative
30-second default for a production-sized package surface. These are hard
per-invocation ceilings, not reservations; monitor invocation CPU and
subrequest use as the published surface grows.

The generated configuration sets `HUB_REQUEST_SHARDING = "on"`. During an
incident or staged update, operators may set it to `read` to route only
read-only operations through the execution shards, or `off` to send every
request directly to `HubDb`. The execution shards retain no relational rows, so
these transitions require neither data migration nor dual-write reconciliation.
The `x-aos-hub-shard` response header identifies the selected partition, and
`Server-Timing` reports execution-shard and aggregate internal-SQL latency.

The default R2 bucket is `<name>-surfaces`, the default KV title is
`<name>-sessions`, and the default Queue is `<name>-jobs`. Override them with
`--bucket`, `--kv-title`, and `--queue` when names must fit an existing account
convention.

Attaching a custom domain to the R2 bucket does not implicitly configure Hub
delivery. Record that infrastructure through the Hub API: create the domain,
endpoint, gateway, and route resources, then select the route independently for
the `git`, `web`, and `nix_cache` audiences. The same topology is visible and
mutable through the CLI, API, and Web console; deploy flags never create hidden
delivery state.

Rate-limit namespace IDs are account-wide. The installer reserves three
consecutive IDs above `--rate-limit-namespace-base`; its default base of `1000`
preserves production IDs `1001` through `1003`. Every independent installation
in the same account must use another non-overlapping base.

## Record and protect secrets

The first deployment mints `HUB_JWT_SECRET` and `HUB_SEAL_KEY` when you do not
supply them. They are printed once. Record both in your secret store.

- `HUB_JWT_SECRET` signs bearer access tokens. Rotating it invalidates issued
  JWTs; browser sessions are opaque records in Durable Object SQLite.
- `HUB_SEAL_KEY` protects stored credentials and signing material. Replacing
  it without migrating sealed data can make that data unreadable. It is also
  needed for an out-of-band root bootstrap or reset.

An ordinary redeploy without secret flags preserves the deployed values. Do
not pass newly generated values to routine updates.

Provider credentials should come from `CLOUDFLARE_API_TOKEN` or `worker login`;
do not put an API token on the command line. The Worker also requires its own
scoped `HUB_CLOUDFLARE_API_TOKEN` described above. Later deploys preserve the
stored runtime token when the variable is omitted. Feed the root password over
stdin.

## Update the deployment

Build the new installer and deploy it with the same Worker name:

```sh
nix build .#pkg-aos-hub-cloudflare
./result/bin/aos-hub worker deploy --name aos-hub
```

Omitting `--domain` during a routine redeploy preserves the existing domain
bindings. When you do provide `--domain`, repeat it for every domain that the
installer should manage; the supplied list becomes the complete managed set.
The `workers.dev` address remains enabled.

Pass `--deployment-id` with an immutable source or build identifier when an
external deployment controller needs to verify rollout. The Worker exposes the
value at `/.well-known/aos-deployment` with `Cache-Control: no-store`; a
controller should reject redirects and compare the response exactly before
declaring the deployment healthy.

The colocated database uses the stable Durable Object name `hub` by default.
Routine updates must keep that name. `--database-instance <name>` explicitly
selects a different, initially empty database for a restore or cutover; after a
cutover, pass the same name on every subsequent deployment. Switching the name
does not migrate accounts, tokens, topology, or publication state.

Worker state is administered through the web console and API. Local
`aos-hub --root ...` commands do not open the Durable Object database.

To create the root account after a deploy, or reset its password later, call
the idempotent seal-gated bootstrap endpoint through the installer:

```sh
printf '%s\n' "$NEW_ROOT_PASSWORD" | \
  HUB_SEAL_KEY="$DEPLOYMENT_SEAL_KEY" \
  ./result/bin/aos-hub worker bootstrap-root \
    --url https://hub.example.com \
    --email ops@example.com \
    --password-stdin
```

## Configure email

Password and passkey sign-in work without outbound email. Magic links require
one of these production paths:

- `--email-from <verified-address>` to use Cloudflare Email Service after the
  sender is onboarded in Cloudflare Email Sending;
- `--email-relay-url <https-url>` with an optional `--email-api-token` for an
  HTTP relay.

If neither is configured, messages are written to logs, which is useful for
development but not a delivery mechanism.

## Configure observability

Worker observability is enabled by default with full head sampling. Adjust it
with `--head-sampling-rate`, disable it with `--no-observability`, or request
Logpush with `--logpush`. The Logpush flag configures the Worker integration;
it does not create the destination that receives those logs.

The Worker does not expose the native server's `/healthz` or `/metrics`
endpoints. Use Workers Logs and metrics for runtime signals, plus an
application-level probe of a public Hub route.

After an install or update, open the Hub, sign in, read a public registry, and
exercise an authenticated operation. The repository builds the packaged Worker
and exercises managed-registry bootstrap and reads against a local SQLite
Durable Object. Only a deployment in your account validates the full request
surface, account policy, custom domains, email, and provider-side observability.
