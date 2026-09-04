# Deploy the hosted AOS Hub

The ANDYL-hosted staging and production Hubs are deployed manually by an
operator. The packaged `aos-hub-cloudflare` installer invokes its bundled
Wrangler, and Wrangler uses the operator's interactive Cloudflare OAuth session.
The repository does not build or deploy the Hub in GitHub Actions.

Manual deployment keeps the hermetic AOS build on a trusted build host with the
appropriate Nix store and builders. It also prevents an ephemeral CI runner from
attempting to bootstrap the AOS package graph before every Worker update.

## Keep the environments isolated

Staging and production share code but not mutable provider resources or secret
values:

| Concern | Staging | Production |
| --- | --- | --- |
| Public origin | `https://aos.staging.andyl.org` | `https://aos.andyl.org` |
| Direct R2 CDN | `https://cdn.aos.staging.andyl.org` | Not configured |
| Worker | `aos-hub-staging` | `aos-hub` |
| R2 bucket | `aos-hub-staging-surfaces` | `aos-hub-surfaces` |
| KV namespace title | `aos-hub-staging-sessions` | `aos-hub-sessions` |
| Deferred-jobs Queue | `aos-hub-staging-jobs` | `aos-hub-jobs` |
| Durable Object state | `hub-v2` on the staging Worker | `hub` on the production Worker |
| Rate-limit namespace IDs | `2001` through `2003` | `1001` through `1003` |

Cloudflare rate-limit namespace IDs are account-wide counter identities, not
local binding names. Reusing production IDs in staging would make traffic in one
environment consume the other's budget.

Use separate values for every environment secret. Worker-direct egress is the
default and requires no separately deployed service. If an optional egress
router is selected, it may be shared only when it recognizes distinct staging
and production key IDs and key material; its staging authorization must not
grant production access.

Do not point a pull request deployment at either environment. Give any future
preview a unique Worker name, bucket, KV namespace, Durable Object state,
rate-limit namespace range, hostname, and secrets. Preview deployments must
never receive production secrets.

## Prepare one immutable installer

Check out the exact `master` commit to deploy and build its packaged Cloudflare
installer on a trusted build host:

```sh
git switch master
git pull --ff-only origin master

deployment_id="$(git rev-parse HEAD)"
installer="$(nix build .#pkg-aos-hub-cloudflare --no-link --print-out-paths)"
test -x "$installer/bin/aos-hub"
```

Keep `deployment_id` and `installer` unchanged through staging validation and
production promotion. Do not rebuild between environments. If the Nix store may
garbage-collect the closure before promotion, copy it to an operator-controlled
binary cache or archive and restore that exact store path before continuing.

## Authenticate Wrangler with Cloudflare OAuth

Start an interactive Wrangler login through the packaged installer:

```sh
unset CLOUDFLARE_API_TOKEN
"$installer/bin/aos-hub" worker login
"$installer/bin/aos-hub" worker whoami
```

The login opens Cloudflare's authorization page in a browser and stores the
Wrangler OAuth credentials locally. Inspect `worker whoami` before every
deployment and stop unless it names the intended Cloudflare account. The
operator credential is inherited by Wrangler; it is not uploaded as a Worker
secret.

Use `worker logout` when the local OAuth session should be removed:

```sh
"$installer/bin/aos-hub" worker logout
```

## Manage Worker runtime secrets

Load runtime values from the operator's secret manager. Do not commit them or
confuse them with Wrangler's OAuth credential.

Every staging deployment supplies its independently generated values for:

- `HUB_CLOUDFLARE_API_TOKEN`
- `HUB_JWT_SECRET`
- `HUB_SEAL_KEY`
- `HUB_ROUTE_RESERVATION_KEYRING`
- `HUB_RELEASE_EVIDENCE_CONFIG`

Production requires its own `HUB_CLOUDFLARE_API_TOKEN` and
`HUB_ROUTE_RESERVATION_KEYRING`. Routine production updates deliberately leave
`HUB_JWT_SECRET` and `HUB_SEAL_KEY` unset so the installer preserves the values
already stored on the Worker. Supplying either is an intentional rotation: a
JWT change invalidates tokens, while an unplanned seal change can make stored
credentials and signing material unreadable.

`HUB_ROUTE_RESERVATION_KEYRING` contains JSON content. Write it to a
permission-restricted temporary file for the installer:

```sh
umask 077
keyring="$(mktemp)"
printf '%s' "$HUB_ROUTE_RESERVATION_KEYRING" > "$keyring"
release_evidence_config="$(mktemp)"
printf '%s' "$HUB_RELEASE_EVIDENCE_CONFIG" > "$release_evidence_config"
```

The atomic release-evidence secret has this closed schema:

```json
{
  "schema_version": "aos.hub.release-evidence-config/v1",
  "publication_key_id": "environment-publication-key-id",
  "publication_signing_seed_base64": "...",
  "channel_key_id": "environment-channel-key-id",
  "channel_signing_seed_base64": "...",
  "publication_keys": {"trusted-staging-key-id": "..."},
  "qualification_keys": {"qualification-authority-id": "..."}
}
```

Publication and channel key identities and material must differ. Staging may
use an empty `publication_keys` map because it does not import another Hub's
receipt. Production pins the staging publication key in that map. Both
environments pin only approved qualification authorities. Each environment has
different signing seeds and a different secret document. The installer
validates the entire document before provider mutation and uploads it with one
atomic secret write; omitting the file on a routine update preserves the
existing secret. Never place the document in Wrangler variables, generated
configuration, logs, or the repository.

Remove both temporary files after the deployment session.

## Deploy staging

Confirm that the shell contains the staging runtime values, then deploy:

```sh
"$installer/bin/aos-hub" worker deploy \
  --name aos-hub-staging \
  --domain aos.staging.andyl.org \
  --external-url https://aos.staging.andyl.org \
  --deployment-id "$deployment_id" \
  --database-instance hub-v2 \
  --rate-limit-namespace-base 2000 \
  --email-from noreply+aos@send.andyl.org \
  --route-reservation-keys-file "$keyring" \
  --release-evidence-config-file "$release_evidence_config"
```

Use `worker install` instead of `worker deploy` only when the staging Worker has
never existed. `worker deploy` deliberately requires an existing Worker so an
OAuth, account, or provider failure cannot be mistaken for initial provisioning.
The `hub-v2` database name is the staging schema-v2 cutover completed in August
2026. Keep it on every subsequent staging deployment; the legacy `hub` object is
retained only as rollback data and is not compatible with this Worker schema.

### Configure the direct staging CDN

Connect
`cdn.aos.staging.andyl.org` to the `aos-hub-staging-surfaces` bucket from the
Cloudflare R2 custom-domain UI or its provider API. Then use the Hub CLI or API
to create an explicit domain, endpoint, gateway, and route for that attachment;
grant each instance-owned resource to the consuming organization and advertise
the route for `git`, `web`, and `nix_cache`. A deployment must not synthesize
topology or grants from Worker bindings, custom domains, or environment
variables. Operators must be able to inventory the complete effective
configuration through the same CLI, API, and Web console used to change it.

The first install provisions the R2 bucket, KV namespace, Durable Object
migration, custom domain, and Worker secrets. After the first successful install,
bootstrap the staging owner once:

```sh
printf '%s\n' "$STAGING_ROOT_PASSWORD" | \
  HUB_SEAL_KEY="$HUB_SEAL_KEY" \
  "$installer/bin/aos-hub" worker bootstrap-root \
    --url https://aos.staging.andyl.org \
    --email ops@example.com \
    --password-stdin
```

Keep staging identities and registry data separate from production.

## Validate staging

Require the hosted deployment identity to equal the source commit:

```sh
curl_package="$(nix build .#pkg-curl --no-link --print-out-paths)"
actual="$(
  "$curl_package/bin/curl" \
    --fail-with-body \
    --proto '=https' \
    --silent \
    --show-error \
    --header 'cache-control: no-cache' \
    "https://aos.staging.andyl.org/.well-known/aos-deployment?manual=$deployment_id"
)"
test "$actual" = "$deployment_id"
```

Also validate the stateful and authenticated paths that the identity probe does
not cover:

- sign in and perform an authenticated administration operation;
- browse public registries, caches, releases, and images;
- exercise a private route with its intended authentication mode;
- publish a disposable release, confirm indexing, and fetch its exact bytes;
- verify full and ranged image downloads, integrity metadata, and cache headers;
- inspect Workers logs and Cloudflare metrics for errors.

Record the commit SHA, installer store path, validation results, operator, and
deployment time before production promotion.

## Promote the same installer to production

Keep the exact validated `installer` and `deployment_id`. Replace the shell's
staging runtime values with production values, and explicitly remove the staging
JWT and seal values:

```sh
unset HUB_JWT_SECRET HUB_SEAL_KEY
printf '%s' "$HUB_ROUTE_RESERVATION_KEYRING" > "$keyring"
```

Pass the complete set of production custom domains as repeated `--domain`
arguments. The set must include `aos.andyl.org`; omitting another managed domain
would remove it from the generated Worker configuration.

```sh
"$installer/bin/aos-hub" worker deploy \
  --name aos-hub \
  --domain aos.andyl.org \
  --external-url https://aos.andyl.org \
  --deployment-id "$deployment_id" \
  --rate-limit-namespace-base 1000 \
  --email-from noreply+aos@send.andyl.org \
  --route-reservation-keys-file "$keyring" \
  --release-evidence-config-file "$release_evidence_config"
```

Repeat `--domain DOMAIN` for every additional domain owned by the production
Worker. Probe `https://aos.andyl.org/.well-known/aos-deployment` exactly as for
staging, then repeat the relevant hosted acceptance tests.

## Optional outbound router and ingress attestation

No outbound gateway, VM, metal host, or VPC connector is required for the normal
Worker deployment. The Worker directly reaches public HTTPS endpoints through
Cloudflare's mediated Fetch implementation.

For a deployment that requires connect-time DNS pinning and signed connected-
peer evidence, deploy the packaged `aos-hub-egress` router independently, then
pass both `--egress-gateway-url https://router.example/v1/fetch` and
`HUB_EGRESS_GATEWAY_KEY=KEY_ID:KEY` to the installer. The installer authenticates
the router contract and stages its overlap key before selecting the router URL.
On first install only, it uses a direct-Fetch bootstrap version until that first
secret set is complete. Router rotations keep the existing router selected;
every old and new router replica must accept both key IDs for the bounded
rotation window. Removing both values returns the generated Worker configuration
to direct mode. The packaged router accepts only public, globally routable
upstream peers; it is not private-network connectivity and is not part of the
Worker-only availability path.

`HUB_DELIVERY_ATTESTATION_KEY` is also optional. Configure it only when a trusted
upstream TLS, VPN, or layer-7 adapter sends authenticated delivery assertions.
Pass `--disable-delivery-attestation` when the complete desired configuration
uses the standard Cloudflare edge path; this also removes a key left by an
earlier attested deployment.

## Roll back deliberately

To roll back code, deploy an earlier installer closure whose application and
database expectations are compatible with the current Durable Object state.
Use that closure's recorded source commit as `--deployment-id` and validate it
in staging before production.

Deploying older Worker code does not reverse SQLite migrations, R2 writes, KV
changes, or published content. For a state rollback, use Cloudflare backups and
the recovery procedure. Treat an incompatible schema migration as a release
requiring an explicit forward repair or data-restore plan.
