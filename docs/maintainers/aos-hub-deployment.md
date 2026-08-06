# Deploy the hosted AOS Hub

The repository deploys one shared staging Hub from `master` and promotes an
already-tested staging artifact to production only through a manually approved
workflow. Pull requests do not deploy into the shared staging environment.

This keeps deployment ownership unambiguous when several pull requests are open:

1. Pull requests build and test immutable code without mutating a shared Hub.
2. A merge to `master` starts **Deploy Hub staging**.
3. Staging deployment runs are serialized. If several commits merge quickly,
   the running deployment finishes and GitHub retains only the newest pending
   run, so staging converges on the newest `master` commit.
4. An operator validates the hosted staging Hub.
5. The operator runs **Promote Hub production**, supplies the successful staging
   run ID, and approves the protected `production` environment.
6. Production imports and deploys the exact Nix closure retained by staging. It
   does not rebuild the commit.

The staging artifact is retained for 30 days. This bounds the promotion window
and provides provenance from the production deployment back to a successful
staging run and source commit.

## Keep the environments isolated

Staging and production share code but not mutable provider resources or secret
values:

| Concern | Staging | Production |
| --- | --- | --- |
| Public origin | `https://aos.staging.andyl.org` | `https://aos.andyl.org` |
| Worker | `aos-hub-staging` | `aos-hub` |
| R2 bucket | `aos-hub-staging-surfaces` | `aos-hub-surfaces` |
| KV namespace title | `aos-hub-staging-sessions` | `aos-hub-sessions` |
| Durable Object state | Owned by the staging Worker | Owned by the production Worker |
| Rate-limit namespace IDs | `2001` through `2003` | `1001` through `1003` |
| GitHub environment | `staging` | `production` |

Cloudflare rate-limit namespace IDs are account-wide counter identities, not
local binding names. Reusing production IDs in staging would make traffic in one
environment consume the other's budget. The workflows pass distinct namespace
ranges to the installer for that reason.

Use separate values for every environment secret. An egress service may be
shared only when it recognizes distinct staging and production key IDs and key
material; its staging authorization must not grant production access.

Do not point a pull request deployment at either environment. If per-PR previews
are added later, give each preview a unique Worker name, bucket, KV namespace,
Durable Object state, rate-limit namespace range, hostname, secrets, and an
automatic teardown. Preview deployments must never receive production secrets.

## Configure GitHub environments

Create `staging` and `production` environments in the repository settings.
Restrict both to the `master` branch. Configure at least one required reviewer
for `production`; the staging environment does not require approval because a
merge to `master` is its deployment gate.

Set these secrets independently in both environments:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN`
- `HUB_CLOUDFLARE_API_TOKEN`
- `HUB_DELIVERY_ATTESTATION_KEY`
- `HUB_EGRESS_SHARED_KEY`
- `HUB_JWT_SECRET`
- `HUB_ROUTE_RESERVATION_KEYRING`
- `HUB_SEAL_KEY`

For the existing production Hub, populate `HUB_JWT_SECRET` and `HUB_SEAL_KEY`
with the exact currently deployed values. Supplying different values is an
intentional rotation: a JWT change invalidates tokens, while an unplanned seal
change can make stored credentials and signing material unreadable. Do not run
the production workflow until those values have been recovered from the
authoritative secret store.

Set `HUB_HARDENED_EGRESS_URL` as an environment variable. In the production
environment, also set `HUB_MANAGED_DOMAINS` to the complete newline-delimited
set of custom domains owned by the production Worker. The list must include
`aos.andyl.org`; making the complete set explicit lets a first deployment bind
the canonical hostname without dropping typed delivery domains during an
update. Staging has one fixed managed domain, `aos.staging.andyl.org`.

Environment-scoped values with the same names let both workflows remain
identical while GitHub selects the correct deployment boundary.

The Cloudflare token needs only the permissions required to deploy the Worker
and manage its R2, KV, Durable Object, route, and secret resources. Scope it to
the account and zones used by that environment. The Hub's own scoped Cloudflare
token (`HUB_CLOUDFLARE_API_TOKEN`) is runtime configuration for route-control
observation and should have only those narrower permissions.

`HUB_ROUTE_RESERVATION_KEYRING` contains the JSON keyring content, not a path.
The workflow writes it to a permission-restricted temporary file before invoking
the installer. Do not commit any of these values.

## Bootstrap staging once

Before enabling automatic deployment, ensure that the `andyl.org` zone belongs
to the deployment account and that the account can create the
`aos.staging.andyl.org` custom domain. Configure the staging egress authorization
and all GitHub environment values above.

The deployment workflow provisions and updates the Worker resources but does not
create the first Hub owner. After the first successful deployment, bootstrap the
staging owner once with the packaged installer and the staging seal key:

```sh
printf '%s\n' "$STAGING_ROOT_PASSWORD" | \
  HUB_SEAL_KEY="$STAGING_HUB_SEAL_KEY" \
  ./result/bin/aos-hub worker bootstrap-root \
    --url https://aos.staging.andyl.org \
    --email ops@example.com \
    --password-stdin
```

Keep staging test identities and registry data separate from production. Seed
the minimum representative public and private fixtures required for hosted
acceptance testing.

## Validate and promote

The staging workflow probes a non-cacheable Worker endpoint and requires its
deployment identity to equal the merged source commit. Production performs the
same comparison against the exact staged artifact and rejects redirects, so a
stale route or another service at the hostname cannot satisfy the check. Before
a production promotion, also validate the stateful and authenticated paths that
this identity probe cannot cover:

- sign in and perform an authenticated administration operation;
- browse public registries, caches, releases, and images;
- exercise a private delivery route with its intended authentication mode;
- publish a disposable release, confirm indexing, and fetch its exact bytes;
- verify full and ranged image downloads, integrity metadata, and cache headers;
- inspect Workers logs and provider metrics for errors.

Open the successful **Deploy Hub staging** run and copy its numeric run ID. Run
**Promote Hub production** from the `master` branch and supply that ID. The
promotion workflow rejects runs from another workflow, branch, trigger, or
conclusion, then imports the exact staged artifact. Approve the protected
`production` environment only after hosted validation is complete.

## Roll back deliberately

To roll back code, promote an earlier successful staging run whose artifact is
still retained. First confirm that its application and database expectations are
compatible with the current Durable Object state. Deploying older Worker code
does not reverse SQLite migrations, R2 writes, KV changes, or published content.

For a state rollback, use the provider backups and recovery procedure rather than
the code-promotion workflow. Treat an incompatible schema migration as a release
requiring an explicit forward repair or data-restore plan.
