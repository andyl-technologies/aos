# Operate AOS Hub in production

AOS Hub has two deployment models:

- the native server is one process with a SQLite system of record and local or
  S3-compatible storage;
- the Cloudflare Worker uses Durable Object SQLite, R2, KV, provider rate
  limits, and scheduled maintenance.

Choose the model before provisioning data. The local `aos-hub` operator CLI
cannot administer a Worker's Durable Object database, and the native state
directory is not a Worker backup format.

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

Bind the native service to loopback and set its public origin:

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

Initialize a native instance as the service account while it is stopped:

```sh
systemctl stop aos-hub.service
printf '%s\n' "$ROOT_PASSWORD" | \
  systemd-run --pipe --wait --collect \
    --uid=aos-hub --gid=aos-hub \
    aos-hub --root /var/lib/aos-hub init \
      --root-email ops@example.com \
      --root-password-stdin
systemctl start aos-hub.service
```

Do not initialize as root; root-owned SQLite or WAL files prevent the
sandboxed service from writing its state.

For the Worker, use the installer bootstrap flow in
[Deploy AOS Hub to Cloudflare](cloudflare.md). Record `HUB_JWT_SECRET` and
`HUB_SEAL_KEY` when the first deployment generates them.

Set the signup policy explicitly. `invite_only` is the normal starting point
for an organizational Hub:

```sh
aos-hub --root /var/lib/aos-hub \
  instance set-signup-policy invite_only
aos-hub --root /var/lib/aos-hub \
  instance show-signup-policy
```

Local operator commands bypass public HTTP authorization. Limit shell and
state-directory access accordingly.

## Configure identities and automation

Use narrowly scoped provisioning tokens. The secret is printed once and the
Hub stores only its hash:

```sh
aos-hub --root /var/lib/aos-hub \
  token mint acme/platform/cdn \
    --permission publish \
    --owner release-bot \
    --expires-days 30
```

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
authenticated Web console or the remote `aos hub org identity-provider`
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
start a compatible Hub build, and verify:

```sh
curl -fsS http://127.0.0.1:8420/healthz
aos-hub --root /var/lib/aos-hub org list
aos-hub --root /var/lib/aos-hub registry list
aos-hub --root /var/lib/aos-hub cache list
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
complete provider backup or cross-account restore tool. Prove recovery in a
separate Worker name and storage namespace.

Protect `HUB_SEAL_KEY` as recovery-critical material. Replacing it without
migrating sealed data can make OIDC credentials, storage credentials, and
hosted signing keys unreadable. Rotating `HUB_JWT_SECRET` intentionally
invalidates issued access tokens.

## Control storage growth

Set organizational quotas before onboarding publishers:

```sh
aos-hub --root /var/lib/aos-hub \
  org set-quota acme \
    --max-bytes 536870912000 \
    --max-objects 5000000 \
    --max-registries 20 \
    --max-tokens 100
```

For a managed cache, link registry roots and set an explicit retention policy:

```sh
aos-hub --root /var/lib/aos-hub \
  cache link acme-cache acme-cdn \
    --roots-packages --advertise

aos-hub --root /var/lib/aos-hub \
  cache gc-policy acme-cache \
    --max-bytes 214748364800 \
    --ttl 14d \
    --keep-versions 3 \
    --schedule 6h
```

Preview a native sweep before deletion:

```sh
aos-hub --root /var/lib/aos-hub \
  cache gc acme-cache --dry-run
aos-hub --root /var/lib/aos-hub \
  cache roots acme-cache
```

The native server records a schedule in policy but does not currently run
scheduled cache GC from its background loop. Invoke `cache gc` from a reviewed
timer or runbook after the dry run. The Worker cron path evaluates scheduled
cache GC policies.

Pin release or incident artifacts that must survive normal retention:

```sh
aos-hub --root /var/lib/aos-hub \
  cache pin acme-cache STORE_HASH --ttl 30d
```

## Monitor the service

For the native server, collect:

- `/healthz` availability and latency;
- registry states, especially `failed` and persistent `stale`;
- webhook pending and failed counts;
- cache objects, bytes, GC runs, and reclaimed bytes;
- process restarts, memory, filesystem space, and SQLite errors;
- public registry, Git, NAR, and authenticated API probes.

The systemd unit uses `Type=simple`, restarts with backoff, and fails after a
bounded crash loop. The binary does not emit systemd readiness or watchdog
notifications.

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
4. Revoke affected provisioning tokens or memberships.
5. Preserve signing and sealing keys before replacing state.
6. Restore into isolation and verify before returning traffic.
7. Reindex registries and validate representative cache objects.
8. Record releases and channel partitions published during the incident.

Do not delete a bad package version as the first response. Stop rollout,
preserve evidence, and follow the registry trust and fix-forward procedure.
