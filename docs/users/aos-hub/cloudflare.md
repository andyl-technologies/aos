# Deploy AOS Hub to Cloudflare

The Cloudflare deployment runs the shared Hub request surface in a Worker. Its
system of record is SQLite inside a `HubDb` Durable Object; registry and cache
bytes live in R2, and KV caches session and hot-key state. The schema migrates
on first use.

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
| `HubDb` Durable Object | SQLite system of record and serialized application requests |
| R2 bucket | Registry and binary-cache surfaces |
| KV namespace | Read-through cache for sessions, revocations, and hot point state |
| Coordinator Durable Object | Publish lease coordination |
| Rate-limit bindings | Edge request budgets |
| Scheduled trigger | Fifteen-minute maintenance and indexing backstop |
| Worker assets | Web interface static files |

The default R2 bucket is `<name>-surfaces`; the default KV title is
`<name>-sessions`. Override them with `--bucket` and `--kv-title` when names
must fit an existing account convention.

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
do not put an API token on the command line. Feed the root password over stdin.

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
