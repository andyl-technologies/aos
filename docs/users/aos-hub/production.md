# Operate AOS Hub in production

AOS Hub has two deployment models:

- the native server is one process with a SQLite system of record and local or
  S3-compatible storage;
- the Cloudflare Worker uses Durable Object SQLite, R2, KV, provider rate
  limits, and scheduled maintenance.

Choose the model before provisioning data. The local `aos-hub` command
cannot open a Worker's Durable Object database, and the native state
directory is not a Worker backup format. Both models are administered through
the console and the remote `aos hub` client; the examples below assume an
`aos hub login` session with sufficient authority.

Use [Trust an internal AOS Hub deployment](trust.md) to assign signing,
administrative, storage, and client-bootstrap authority before deployment.

## Choose a topology

Use the native server when the organization wants direct control of the
database, storage, service lifecycle, and network. It is a single-instance
SQLite service today. Do not place two native Hub processes over the same state
directory or shared SQLite file, and do not describe it as active-active.

Use the Worker when provider-managed edge deployment, R2 storage, and Durable
Object serialization fit the operating model. Recovery, logs, domains, and
resource limits then depend on the Cloudflare account and its retention.

For either model, separate the Hub system of record, object storage, public DNS
and TLS, authentication material, backups, and observability.

## Put the native server behind TLS

The native server can terminate TLS itself; see
[Terminate TLS](native.md#terminate-tls). To use a reverse proxy instead,
bind the native service to loopback and set its public origin:

```nix
{
  aos.registry-hub = {
    enable = true;
    listen = "127.0.0.1:8420";
    externalUrl = "https://hub.example.com";
  };
}
```

Terminate TLS in a reverse proxy or load balancer that preserves the original
`Host` header, supports streaming bodies, allows the required upload size and
duration, and probes `/healthz` on the private listener.

The native server does not currently trust forwarded client-address headers.
Its pre-authentication rate limiter therefore sees the proxy peer rather than
individual clients. Account for that before placing many users behind one
proxy, and do not trust arbitrary forwarding headers at the edge.

Verify the public path, not only loopback:

```sh
curl -fsS http://127.0.0.1:8420/healthz
curl -fsS https://hub.example.com/healthz
curl -fsS https://hub.example.com/metrics | sed -n '1,40p'
```

Restrict `/metrics` at the proxy if operational inventory should not be public.
The application route itself does not require authentication.

## Bootstrap administrative access

Initialize a native instance as the service account while it is stopped,
never as root. The exact commands are in
[Configure the AOS service module](native.md#configure-the-aos-service-module).
If the owner password is lost, `aos-hub reset-root --email <address>
--password-stdin` resets it against the same state root, under the same
service-account rule.

For the Worker, use the installer bootstrap flow in
[Deploy AOS Hub to Cloudflare](cloudflare.md). Record `HUB_JWT_SECRET` and
`HUB_SEAL_KEY` when the first deployment generates them.

Confirm the signup policy explicitly. `invite_only` is the default and the
normal starting point for an organizational Hub; `open` is the alternative.
Read the identity settings and their revision, then plan and apply a change:

```sh
aos hub instance identity show

aos hub instance identity update plan signup_policy=invite_only \
  --if-version '<settings-revision>' \
  --idempotency-key plan-signup-policy
aos hub instance identity update apply \
  --plan-id '<plan-id>' --confirm-hash '<hash>' \
  --idempotency-key apply-signup-policy --yes
```

The local `aos-hub init`, `reset-root`, and `index` commands bypass public HTTP
authorization. Limit shell and state-directory access accordingly.

## Configure identities and automation

Use narrowly scoped tokens owned by a service account. Create the account,
copy the registry's canonical scope from `aos hub whoami`, then plan and apply
the token:

```sh
aos hub org service-account create plan acme release-bot \
  --idempotency-key plan-create-release-bot
aos hub org service-account create apply \
  --plan-id '<plan-id>' --confirm-hash '<hash>' \
  --idempotency-key apply-create-release-bot --yes

aos hub access-token issue plan \
  'registry:0123456789abcdef0123456789abcdef' \
  --owner 'service_account:acme/release-bot' \
  --permission publish \
  --ttl-secs 2592000 \
  --comment 'release publisher' \
  --idempotency-key plan-release-bot-token
aos hub access-token issue apply \
  --plan-id '<plan-id>' --confirm-hash '<hash>' \
  --idempotency-key apply-release-bot-token --yes
```

The server rechecks the owner's current role authority when applying the
plan. The secret is
printed once by the first successful apply and the Hub stores only its hash.
Tokens default to 30 days and cannot exceed 90.

Store the token immediately. Automation may exchange it through the explicit
provisioning grant with:

```sh
aos hub login \
  --hub https://hub.example.com \
  --provisioning-token "$AOS_PROVISIONING_TOKEN"
```

Grant broader roles only when the operation requires them. Publishing package
objects does not require instance administration.

OIDC configuration supports issuer and endpoint metadata, JWKS, group-to-role
mapping, enforced SSO, and optional just-in-time provisioning. Use the
console or the remote `aos hub org identity-provider`
commands. The remote CLI reads a replacement credential from
`AOS_OIDC_CLIENT_SECRET`; it does not require the secret in process arguments.
Claim email domains separately with `aos hub org domain`. Verification resolves
the exact reviewed DNS TXT challenge before the domain can route sign-ins.

Retain a tested local owner recovery path before enforcing SSO. Verify issuer
reachability, TLS, time synchronization, group claims, default role, and
behavior when the identity provider is unavailable.

## Back up a native Hub

The recovery set consists of:

- `hub.db` and any SQLite WAL files;
- `secret.key`, or the file named by `AOS_HUB_SECRET_KEY_FILE`;
- local registry and cache bindings;
- externally stored S3-compatible objects at a consistent point;
- reverse-proxy and AOS service configuration;
- external domains, IdP settings, and recovery identities.

The safest simple backup stops the service and snapshots the complete state
root and bound storage together:

```sh
systemctl stop aos-hub.service
test -f /var/lib/aos-hub/hub.db
test -f /var/lib/aos-hub/secret.key

# Snapshot or copy the complete state and bound storage here.

systemctl start aos-hub.service
curl -fsS http://127.0.0.1:8420/healthz
```

If the service cannot stop, use SQLite's online-backup mechanism and a storage
snapshot procedure with defined object/database ordering. Copying a live
`hub.db` while ignoring its WAL files is not a backup.

Test restoration on an isolated listener. Restore service-account ownership,
start a compatible Hub build, sign in to the restored instance, and verify:

```sh
curl -fsS http://127.0.0.1:8420/healthz
aos hub login --hub '<restored-hub-url>'
aos hub org list
aos hub registry list
aos hub cache list
```

Then exercise sign-in, a private read, package publication, registry indexing,
and a cache download. A database-only test does not prove that sealed
credentials or storage objects survived.

Without a configured JWT credential, native access-token signing keys are
regenerated when the process starts, so existing one-hour JWTs stop working
after restart. When the AOS service supplies `credentials.jwtSecret`, that
runtime credential persists the signing authority across restarts and must be
included in the deployment's secret backup and rotation plan. Durable
provisioning tokens can be exchanged again in either case.

## Back up a Worker deployment

Worker state lives in provider resources, not a local directory. Define
account-level retention and export procedures for Durable Object SQLite, R2,
KV, deployed Worker configuration, secrets, domains, and log destinations.

The packaged installer deploys and migrates the application; it is not a
complete provider backup or cross-account restore tool. For the database
alone, it can capture and restore a Durable Object SQLite point-in-time
recovery bookmark. Both commands authenticate with the deployment's
`HUB_SEAL_KEY`, read from the environment or `--seal-key`:

```sh
aos-hub worker backup-bookmark --url https://hub.example.com

aos-hub worker restore-bookmark --url https://hub.example.com \
  --bookmark '<bookmark>' \
  --confirm-database-instance '<database-instance>' \
  --confirm-deployment-id '<deployment-id>'
```

`backup-bookmark` captures the current state, or an approximate past time with
`--timestamp-ms`. `restore-bookmark` is destructive: it schedules the restore
for the database's next session and requires the live database instance name
and deployment identity as confirmation. A bookmark covers the database only.
Prove recovery in a separate Worker name and storage namespace.

Protect `HUB_SEAL_KEY` and `HUB_JWT_SECRET` as described in
[Record and protect secrets](cloudflare.md#record-and-protect-secrets).

## Control storage growth

Neither CLI has a command for organization quotas. Bound growth with cache
retention and garbage collection instead. Caches are addressed as
`<org>/<cache>`.

Subscribe a cache to the registry content it must retain. This example keeps
the registry's current catalog closure:

```sh
aos hub cache retention set acme/builds \
  --registry acme/cdn \
  --current-catalog \
  --plan --idempotency-key plan-builds-retention
```

Apply the printed plan with `--plan-id`, `--confirm-hash`, and `--yes`. Other
selectors retain channel targets (`--channel`, `--all-channel-targets`), recent
releases (`--recent-releases`), or exact releases (`--release`).

Review the cache-wide collection policy, which holds the grace period for
unreferenced objects, soft size limits, and the schedule:

```sh
aos hub cache gc policy show acme/builds
```

`aos hub cache gc policy set` replaces the whole policy and requires every
field; run it with `--help` for the list.

Garbage collection is a reviewed plan followed by a run. Create a plan, read
what it would collect and what is still rooted, then run that exact plan:

```sh
aos hub cache gc plan create acme/builds
aos hub cache gc plan show acme/builds '<plan-id>'
aos hub cache retention roots acme/builds

aos hub cache gc run acme/builds \
  --plan-id '<plan-id>' --confirm-hash '<hash>' \
  --idempotency-key run-builds-gc-1 --yes --wait
```

A cache's first destructive sweep has its own acknowledgement gate under
`aos hub cache gc first-sweep`. Inspect earlier runs with
`aos hub cache gc runs list acme/builds`.

Pin release or incident artifacts that must survive normal retention with a
manual root. Omit `--lease-until` for an indefinite root:

```sh
aos hub cache root create acme/builds STORE_HASH \
  --reason 'incident evidence' \
  --plan --idempotency-key plan-pin-incident
```

## Monitor the service

For the native server, collect:

- `/healthz` availability and latency;
- registry states, especially `failed` and persistent `stale`;
- webhook pending and failed counts;
- cache objects, bytes, GC runs, and reclaimed bytes;
- process restarts, memory, filesystem space, and SQLite errors;
- public registry, Git, NAR, and authenticated API probes.

The AOS service module restarts the process after it exits, with a
five-second delay. The binary does not emit systemd readiness or watchdog
notifications, so a running process is not proof of a healthy Hub; probe
`/healthz`.

```sh
systemctl status aos-hub.service
journalctl -u aos-hub.service -b
systemctl show aos-hub.service \
  -p ActiveState -p SubState -p NRestarts -p Result
```

The Worker does not expose native `/healthz` or `/metrics`. Use Workers Logs and
metrics plus public and authenticated application probes.

## Upgrade and roll back

Before a native upgrade, record the current binary, take a recovery point,
stop the service, and start the new binary against the existing root. Startup
applies pending schema migrations. Verify health, login, storage, and
publish/read paths before returning traffic.

A binary rollback is safe only when the older binary supports the migrated
schema. Otherwise restore the pre-upgrade recovery point. For the Worker,
rolling code back does not automatically roll Durable Object schema or stored
data back.

## Incident checklist

1. Preserve logs, version, health output, and recent audit entries.
2. Stop publishers or token exchange if integrity is uncertain.
3. Distinguish database, object storage, public routing, and identity failure.
4. Retire affected access tokens or remove memberships.
5. Preserve signing and sealing keys before replacing state.
6. Restore into isolation and verify before returning traffic.
7. Reindex registries and validate representative cache objects.
8. Record releases and channel partitions published during the incident.

Do not delete a bad package version as the first response. Stop rollout,
preserve evidence, and follow the registry trust and fix-forward procedure.
