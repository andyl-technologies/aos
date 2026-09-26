# Deploy a hybrid AOS Hub

This procedure creates a fresh Worker-fronted Native Hub. Native serves the
website and authoritative API from PostgreSQL. The public Worker serves object
bytes from its R2 binding and forwards bounded control requests to Native.
Native must have no R2 credential. The procedure assumes a new, empty Hub;
it does not convert an existing Worker HubDb or Native SQLite database.

Use one reviewed source commit for both artifacts. Keep the public origin,
Native origin, PostgreSQL instance, R2 bucket, deployment ID, and credentials
distinct for each environment. See [RFC-0023](../rfcs/0023-hub-hybrid-topology/README.md)
for the routing and storage contracts.

## Prepare the paired deployment

1. Build `pkgs.aos-hub`, `pkgs.aos-hub-cloudflare`, and
   `pkgs.aos-hub-worker-dist` from the same commit. Record their store paths,
   the commit, and a unique `deploymentId`. Keep these paths until the
   deployment is qualified.
2. Create a PostgreSQL database near the Native service. Restrict its network
   access to Native. Configure TLS and backup through the database platform.
   Supply its URL through `aos.registry-hub.credentials.databaseUrl`.
3. Create the R2 bucket in the Cloudflare account that will run the Worker.
   The Native service receives neither an R2 binding nor an R2 API token.
4. Issue separate random values for the ingress and storage-work HMAC keys.
   Put the same ingress key in Native's `hybridIngressKey` credential and the
   Worker's `HUB_HYBRID_INGRESS_KEY` secret. Put the same storage key in
   Native's `storageWorkKey` credential and the Worker's
   `HUB_STORAGE_WORK_KEY` secret. Keep these keys distinct from release,
   session, route-reservation, and database credentials.
5. Give the Native origin a private hostname and a certificate valid for that
   hostname. Configure the Worker to reach it over HTTPS. Restrict direct
   origin traffic at the network layer to Cloudflare and trusted probes;
   application ingress authentication remains mandatory. The probe hostname
   should be unused by clients and restricted to operators where the provider
   permits it.

Configure `aos.registry-hub` on the Native host with `hybrid.enable = true`,
`externalUrl` set to the public Worker origin, `hybrid.originUrl` set to the
private Native origin, and `hybrid.workerUrl` set to a dedicated HTTPS probe
hostname on the same Worker. Keep this hostname attached when the public
hostname is added. Set `deploymentId`, `listen`, PostgreSQL and HMAC
credentials, TLS certificate and key, and the release evidence identities and
credentials required by the module. Provision route-reservation and domain-probe
credentials as for the existing Native service. The module passes the paired
URLs and credential file paths to `aos-hub serve --topology hybrid`.

Initialize the empty database with `aos-hub init` using the same
`HUB_DATABASE_URL_FILE` credential and root directory as the service. Migrate
once before opening traffic. The Native service retries startup while its
paired Worker is unavailable; it must become healthy without a manual restart
after the Worker starts. Keep public routing closed during this step.

## Render and deploy the Worker

The packaged `aos-hub-cloudflare` binary contains the matching Worker artifact.
Render a profile with `aos-hub worker render-hybrid-config`:

```sh
installer="$(nix build -f . pkgs.aos-hub-cloudflare --no-link --print-out-paths)"
worker_dist="$(nix build -f . pkgs.aos-hub-worker-dist --no-link --print-out-paths)"
wrangler="$(nix build -f . pkgs.miniflare --no-link --print-out-paths)/bin/wrangler"

mkdir -p hybrid-worker
cp "$worker_dist/shim.mjs" "$worker_dist/index.wasm" hybrid-worker/
cp -r "$worker_dist/assets" hybrid-worker/assets
"$installer/bin/aos-hub" worker render-hybrid-config \
  --name "$worker_name" --bucket "$r2_bucket" \
  --deployment-id "$deployment_id" \
  --external-url "$public_origin" \
  --native-origin-url "$native_origin" \
  --domain "$probe_hostname" --serve-assets \
  > hybrid-worker/wrangler.toml
```

Supply the values named above from the reviewed environment plan. Inspect the
generated profile: it has one R2 bucket binding, no HubDb Durable Object, no
session KV or job Queue, and `HUB_TOPOLOGY = "hybrid"`. Use an operator's
Cloudflare deployment identity with the intended account. The first deployment
attaches only the unused probe hostname. Upload the two HMAC secrets immediately
afterward; requests fail closed until both exist. Do not put secrets in
`wrangler.toml` or `.dev.vars` for a hosted deployment.

```sh
cd hybrid-worker
"$wrangler" deploy --config wrangler.toml
"$wrangler" secret put HUB_HYBRID_INGRESS_KEY --config wrangler.toml
"$wrangler" secret put HUB_STORAGE_WORK_KEY --config wrangler.toml
```

The secret commands prompt for values and each publishes a Worker revision;
enter the independently managed keys. If deploying a new Worker name, create
the R2 bucket before `deploy`. Preserve the same secrets on routine updates
unless carrying out a planned paired key rotation.

## Qualify before opening traffic

Check the deployment identity and both private protocols before attaching the
public hostname. An unauthenticated direct request to Native must return 401.
An unsigned storage capability request must return 401. A signed capability
probe from Native must report the exact deployment identity and supported
protocol. A mismatch keeps Native unready; it must not silently use local
storage. Verify the Worker can reach the Native TLS hostname and return a
healthy response through the probe hostname.

Run `nix build -f . checks.fleet.hub-hybrid -L --no-link` for the three-VM
contract test. Its client is separate from the PostgreSQL Native VM and the
Wrangler/R2-emulation Worker VM. For the hosted environment, exercise the same
browser, CLI, Nix cache, publication, OCI, parallel upload, inventory, and
failure paths with representative release data. Record p50/p95/p99 page time
to first byte, upload impact, Worker and Native request counts, SQL pool use,
and cross-cloud bytes. The [RFC acceptance gates](../rfcs/0023-hub-hybrid-topology/06-implementation-and-validation.md)
apply before promoting the environment.

Only after those probes and recovery checks pass, render the same profile with
both `--domain "$probe_hostname"` and `--domain "$public_hostname"`, then
deploy it. This is the public cutover. Immediately verify public `/healthz`,
`/login`, and an authenticated `/-/instance` page. If qualification fails,
keep or return the public route to the previous deployment. Do not point a
Worker-only HubDb deployment at this PostgreSQL state, or switch a Native
service to hybrid as an implicit data migration. For a fresh staging reset,
retain the old environment separately until its required data is republished
or a restore has been verified.
