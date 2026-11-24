# Deploy AOS Hub as a native service

The native server keeps its system of record in SQLite and serves registry and
cache bytes from local or S3-compatible storage. For internet-facing use,
terminate TLS in the Hub or in a reverse proxy in front of it.

Before choosing where keys and credentials live, read [Trust an internal AOS
Hub deployment](trust.md).

## Initialize the instance

Build the package:

```sh
nix build .#pkg-aos-hub
```

Create the initial instance owner before starting the service. For a standalone
deployment, use a state directory owned by the account running the Hub:

```sh
printf '%s\n' "$ROOT_PASSWORD" | \
  ./result/bin/aos-hub --root ./hub-state init \
    --root-email ops@example.com \
    --root-password-stdin
```

`init` creates or migrates the database and grants that account the Owner role
at the instance root. It is safe to run schema migration again after an update.
Do not put passwords directly on the command line.

Start the server:

```sh
./result/bin/aos-hub --root ./hub-state serve \
  --listen 127.0.0.1:8420 \
  --external-url https://hub.example.com
```

Keep the listener on localhost when a reverse proxy owns the public address.
`--external-url` must be the URL that users and API clients open.

The local `aos-hub` command only starts, initializes, recovers, and re-indexes
the instance. After the server is running, sign in as the instance owner and
administer it through the console or the remote `aos hub` client; see
[Choose the right AOS Hub CLI](cli.md).

## Configure the AOS service module

On an AOS system, enable the service in the build-time system variant:

```nix
{pkgs, ...}: {
  imports = [./server.nix];

  environment.systemPackages = [pkgs.aos-hub];

  aos.registry-hub = {
    enable = true;
    listen = "127.0.0.1:8420";
    externalUrl = "https://hub.example.com";
    credentials = {
      routeReservationKeys = "hub-route-reservation-keys";
      domainProbeSignerManifest = "hub-domain-probe-signers";
      jwtSecret = "hub-jwt-secret";
    };
  };
}
```

Credential values are names in the platform namespace beneath
`/run/credentials/@system`; they are never embedded in Nix evaluation or the
store. Route reservation keys and the domain-probe signer manifest are required.
Optional names cover JWT signing, delivery attestation, route publication,
secret-version manifests, and the Cloudflare API token. When route publication
is enabled, configure its public key beside the credential name:

```nix
{
  aos.registry-hub = {
    credentials.routePublicationManifest = "hub-route-publication-manifest";
    routePublicationPublicKey = "<base64url-ed25519-public-key>";
  };
}
```

The same module can be supplied through authenticated runtime `host.nix`; its
package and service configuration are evaluated into a numbered configuration
generation and activated atomically. Keep release-image capabilities and trust
roots in the image. The [AOS customization guide](../aos/configuration.md)
explains that image/host boundary.

After deploying the image, initialize the database as the service account. The
unit's first start creates `/var/lib/aos-hub`; stop it before initialization so
SQLite has one writer:

```sh
systemctl stop aos-hub.service
printf '%s\n' "$ROOT_PASSWORD" | \
  systemd-run --pipe --wait --collect --uid=aos-hub --gid=aos-hub \
    aos-hub --root /var/lib/aos-hub init \
      --root-email ops@example.com \
      --root-password-stdin
systemctl start aos-hub.service
```

Do not run `init` as root. Root-owned database or WAL files prevent the
sandboxed service account from operating the instance.

The module runs `aos-hub` under a dedicated service account and uses
`/var/lib/aos-hub` for state. Initialize that directory as the service account
before relying on web administration. Keep the default state root; custom
roots also need matching systemd write permissions.

## Terminate TLS

Choose one of two arrangements:

- A reverse proxy terminates TLS, sends the public HTTPS origin to
  `127.0.0.1:8420`, and preserves the request host. The native server does not
  trust forwarded client addresses, so pre-authentication rate limits then
  apply to the proxy peer rather than individual clients.
- The Hub terminates TLS itself. Pass `--tls-certificate-file` and
  `--tls-private-key-file` to `serve` with a PEM certificate chain and its
  matching private key, or set `credentials.tlsCertificate` and
  `credentials.tlsPrivateKey` in the service module. The module requires both
  together and an `https://` `externalUrl`. Each connection must present the
  configured public hostname through SNI.

[Operate AOS Hub in production](production.md#put-the-native-server-behind-tls)
covers proxy requirements and public verification.

## Understand the state

The state root contains:

- `/var/lib/aos-hub/hub.db` and any SQLite WAL files;
- `/var/lib/aos-hub/secret.key`, used to seal stored credentials and hosted
  signing-key material;
- local filesystem bindings placed beneath the state root.

The secret key is created with mode `0600` on first production use. It may also
be supplied from a protected file through `AOS_HUB_SECRET_KEY_FILE`. Losing it
makes sealed values unusable.

The backup procedure, the recovery set beyond the state root, and the effect
of a restart on access tokens are described once in
[Back up a native Hub](production.md#back-up-a-native-hub).

## Add registry storage

Managed registries use named bindings. Create them through the console or the
remote client after signing in as the instance owner:

```sh
aos hub login --hub https://hub.example.com
```

The simplest native binding is a directory writable by the service account.
Plan the organization and the binding, review the printed effects, then apply
each plan:

```sh
aos hub org create --slug acme --display-name "Acme" \
  --plan --idempotency-key plan-org-acme
aos hub org create \
  --plan-id '<plan-id>' --confirm-hash '<hash>' --yes

aos hub binding create --org acme --name primary \
  --kind local-fs --root /var/lib/aos-hub/storage \
  --plan --idempotency-key plan-binding-primary
aos hub binding create --name primary \
  --plan-id '<plan-id>' --confirm-hash '<hash>' --yes
```

The AOS service sandbox can write under `/var/lib/aos-hub`. A binding elsewhere
needs a matching systemd write-path override as well as filesystem ownership.

For S3-compatible storage, create the binding from the organization's storage
page in the console, or with `aos hub binding create --kind s3`. Supply the
bucket and optional prefix, endpoint, signing region, access mode, and
credentials. Private credentials are sealed with the instance key; include
that key in every backup.

Create the registry itself with `aos hub registry create`, passing each pinned
trust anchor as `--trust-key 'name:Ed25519:<base64-public-key>'`, then publish
to it as described in [Host a registry](../registry/hosting.md#aos-hub). The
Hub verifies signed registry data and fails closed. There is no local
`aos-hub` command for adding a registry; `aos hub registry mirror` manages a
registry that follows an existing external source. Run
`aos hub registry mirror --help` for its options.

The local `index` command re-indexes one registry, or all of them when the
slug is omitted, directly against the state root:

```sh
./result/bin/aos-hub --root /var/lib/aos-hub index acme/cdn
```

## Monitor and update

Probe liveness and database access at:

```sh
curl -fsS http://127.0.0.1:8420/healthz
```

Prometheus metrics are served at `/metrics`. They cover indexing, webhooks,
caches, garbage collection, and build/version information.

For a manual binary deployment, build the new package, stop the service, take a
recovery point, and start the new binary against the existing root. Startup
applies pending schema migrations.

For an AOS module deployment, update the containing system variant or sysroot
generation and deploy it through the normal AOS image or userspace-generation
workflow. The unit remains pinned to its old Nix store path until that system
generation changes. After either update path, watch `aos-hub.service` and verify
`/healthz` before returning traffic.

Native magic-link mail currently writes links to the service log rather than
delivering mail. Use password, passkey, or OIDC sign-in for production until an
outbound mailer is configured in the implementation.
