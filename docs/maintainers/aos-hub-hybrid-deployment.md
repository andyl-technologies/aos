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
   Provision stable JWT and instance sealing keys through `jwtSecret` and
   `instanceSecretKey`. Every Native replica must use the same versions.
   Hybrid startup rejects an absent JWT or sealing-key file; it cannot generate
   these keys in an ephemeral local root.
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

## Native container artifact

The dedicated service image is exposed as `container-aos-hub-oci` and
`container-aos-hub-docker` in the flake. `container-aos-hub-index` coordinates
the amd64 and arm64 images; use the platform artifact supported by the selected
GCP runtime. Build the image and Worker from the same reviewed source commit.
The image execs `/usr/bin/aos-hub serve` directly and has no initialized database,
credentials, or package-manager initialization step.

The image defaults to `HUB_TOPOLOGY=hybrid`, `HUB_ROOT=/tmp/aos-hub`, and
`HUB_LISTEN=0.0.0.0:8080`. Supply `HUB_EXTERNAL_URL`, the paired origins and
deployment identity, PostgreSQL, release authority, and the credential-file
variables documented by `aos-hub serve --help`. Configure the platform's
listener port to match `HUB_LISTEN`. Platform TLS termination may front the
HTTP listener; signed hybrid ingress still authenticates each request.

Set `HUB_DNS_JSON_ENDPOINT` to an HTTPS DNS-over-JSON resolver (the systemd
module defaults to `https://dns.google/resolve`). Route-reservation and
domain-probe credential manifests are required before serving, even when the
new instance has no custom domains.

Mount credentials as read-only regular files with private permissions, owned
by root or the workload user, beneath a directory that is not writable by
other users. Set `HUB_JWT_SECRET_FILE` and `AOS_HUB_SECRET_KEY_FILE` to stable
external keys, along with the two paired HMAC key-file variables. The temporary
root is disposable in hybrid because PostgreSQL and the Worker own state; the
sealing key must not live there. Run `init` as a separate operator operation
against the same PostgreSQL URL before admitting requests. Native-only
containers explicitly set `HUB_TOPOLOGY=native` and mount a persistent
owner-private `HUB_ROOT` for SQLite and local object storage.

The GCP application registration must bind the service artifact, listener,
private credential files, and Cloud SQL connection. These platform resources
are owned by the companion infrastructure configuration; the AOS image does
not provision them. Run `nix-build -A checks.fleet.hub-native-container` to
qualify the image in AOS-built containerd/runc before deploying it.

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
storage. The supported operations must include `inspect_metadata_objects` for
batched channel refresh. Verify the Worker can reach the Native TLS hostname
and return a healthy response through the probe hostname.

Run `nix-build -A checks.fleet.hub-hybrid` for the four-VM contract test. The
client, PostgreSQL Native Hub, Wrangler/R2-emulation Worker, and Garage S3
service run on separate machines. The S3 fixture checks purpose-scoped
credential validation, inventory admission, and full, ranged, and HEAD reads
through Native authorization and Worker streaming. For the hosted environment,
exercise the same browser, CLI, Nix cache, publication, OCI, parallel upload,
inventory, and failure paths with representative release data. Record
p50/p95/p99 page time to first byte, upload impact, Worker and Native request
counts, SQL pool use, and cross-cloud bytes. The
[RFC acceptance gates](../rfcs/0023-hub-hybrid-topology/06-implementation-and-validation.md)
apply before promoting the environment.

Native logs each storage-work terminal result with its operation, attempts,
serialized plan bytes, validated result bytes, and Worker source-byte count.
Indexing events also carry a task-scoped `index_run` and `registry_id`; release
walks add `release` and `tag_oid`. Group by run and release before summing.
Keep registry preload and channel work, which lacks a release field, in a
separate shared total. Completion events record the run outcome and release
snapshot reuse, including warm walks with no remote calls.

Multiply `request_bytes` by `attempts` to measure offered plan bytes including
retries. This is serialized application payload, not a provider network bill:
transport failures may prevent delivery, canceled calls have no terminal
result, and TLS/HTTP framing is excluded. `response_bytes` counts only validated
terminal results; rejected and retry response bodies are excluded. The fleet
report retains these distinctions and verifies exact signed release tags in
PostgreSQL, alongside the object-body exclusion checks.

The separate `hybrid storage exchange accounting` event records each plan's
`exchange_attempts`, total `offered_plan_bytes`, `observed_body_bytes`,
`discarded_status_responses`, elapsed time, and final outcome. It is emitted on
success, error, or cancellation after plan encoding, including malformed
responses and response chunks observed before a limit or read failure. Sum
these events independently of the terminal-result counters; adding both would
double-count successful traffic. They inherit the index run and release context.

`discarded_status_responses` counts HTTP error replies dropped without consuming
their bodies. `observed_body_bytes` excludes those bodies, internal client
prefetch, and framing; it is an application observation, not total inbound wire
usage. Offered plans include attempts whose transport may never deliver them.
Use provider network telemetry for billed bytes. Plans, credentials, and object
contents are not included in the accounting event.

Channel refresh batches up to 32 partitions per storage-work call. A warm
registry with two branches needs sixteen channel batches plus its HEAD and
refs checks when documents fit in one page per batch. Larger metadata pages
require additional calls. The fleet fixture verifies a signed populated
channel, bounded warm-refresh call and plan-byte totals, and pagination of
maximum-sized documents through the external S3 adapter. Worker source-byte
counts include documents read concurrently but deferred to the next page;
those documents may be read again on continuation.

For an operator-triggered refresh, run `aos-hub index` with the same database,
deployment identity, and storage-work credentials as the Native service:

```sh
HUB_TOPOLOGY=hybrid \
HUB_DATABASE_URL_FILE="$database_url_file" \
HUB_DEPLOYMENT_ID="$deployment_id" \
HUB_HYBRID_WORKER_URL="$probe_origin" \
HUB_STORAGE_WORK_KEY_FILE="$storage_work_key_file" \
HUB_SECRET_VERSION_MANIFEST_FILE="$secret_version_manifest_file" \
aos-hub index "$registry_slug"
```

Omit the registry slug to refresh all registries. Run as the workload user
with owner-private credential files; omit the secret manifest when no external
provider credentials are needed. The command verifies the paired Worker's
capabilities before indexing and returns a nonzero status if a registry fails.
Native-only indexing uses `HUB_TOPOLOGY=native` and its local storage adapter.

Only after those probes and recovery checks pass, render the same profile with
both `--domain "$probe_hostname"` and `--domain "$public_hostname"`, then
deploy it. This is the public cutover. Immediately verify public `/healthz`,
`/login`, and an authenticated `/-/instance` page. If qualification fails,
keep or return the public route to the previous deployment. Do not point a
Worker-only HubDb deployment at this PostgreSQL state, or switch a Native
service to hybrid as an implicit data migration. For a fresh staging reset,
retain the old environment separately until its required data is republished
or a restore has been verified.
