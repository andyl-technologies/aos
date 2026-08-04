# Deploy AOS Hub as a native service

The native server keeps its system of record in SQLite and serves registry and
cache bytes from local or S3-compatible storage. Put it behind a TLS reverse
proxy for internet-facing use.

## Initialize the instance

Build the package:

```sh
nix build .#pkg-aos-hub
```

Create the initial instance owner before starting the service. Run this as the
same account that will own the Hub state:

```sh
printf '%s\n' "$ROOT_PASSWORD" | \
  ./result/bin/aos-hub --root /var/lib/aos-hub init \
    --root-email ops@example.com \
    --root-password-stdin
```

`init` creates or migrates the database and grants that account the Owner role
at the instance root. It is safe to run schema migration again after an update.
Do not put passwords directly on the command line.

Start the server:

```sh
./result/bin/aos-hub --root /var/lib/aos-hub serve \
  --listen 127.0.0.1:8420 \
  --external-url https://hub.example.com
```

Keep the listener on localhost when a reverse proxy owns the public address.
`--external-url` must be the URL that users and API clients open.

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
  };
}
```

General runtime `host.nix` activation is not complete, so putting this setting
in metadata does not start the service today. Rebuild and deploy the resulting
system image. The [AOS customization guide](../aos/configuration.md) explains
the distinction between image modules and first-boot `host.nix` policy.

After deploying the image, initialize the database as the service account. The
unit's first start creates `/var/lib/aos-hub`; stop it before initialization so
SQLite has one writer:

```sh
systemctl stop aos-hub.service
printf '%s\n' "$ROOT_PASSWORD" | \
  runuser -u aos-hub -- \
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

The service does not terminate TLS. Configure a reverse proxy to send the
public HTTPS origin to `127.0.0.1:8420` and preserve the request host. The
native server does not yet trust forwarded client addresses, so pre-auth rate
limits behind a proxy apply to the proxy peer rather than individual clients.

## Understand the state

Stop the Hub and back up the complete state root. It contains:

- `/var/lib/aos-hub/hub.db` and any SQLite WAL files;
- `/var/lib/aos-hub/secret.key`, used to seal stored credentials and hosted
  signing-key material;
- every local filesystem storage binding used by a registry or cache.

The secret key is created with mode `0600` on first production use. It may also
be supplied from a protected file through `AOS_HUB_SECRET_KEY_FILE`. Losing it
makes sealed values unusable.

When `AOS_HUB_SECRET_KEY_FILE` points outside the Hub state root, back up that
external key file with the same recovery point.

Copy the complete stopped state root as one recovery point. If registry or cache
bindings live elsewhere, include those paths as well. Include the reverse-proxy
and service configuration in the same backup plan. Use SQLite's online-backup
mechanism instead if the service cannot be stopped.

Access JWT signing keys are currently regenerated when the native process
starts. Existing one-hour API access tokens therefore stop working after a
restart; exchange the durable provisioning token again.

## Add registry storage

Managed registries use named storage bindings. The simplest native binding is
a directory writable by the service account:

```sh
./result/bin/aos-hub --root /var/lib/aos-hub \
  org add acme "Acme"
./result/bin/aos-hub --root /var/lib/aos-hub \
  binding add acme primary --path /var/lib/aos-hub/storage
```

The AOS service sandbox can write under `/var/lib/aos-hub`. A binding elsewhere
needs a matching systemd write-path override as well as filesystem ownership.

For S3-compatible storage, create the binding from the organization's storage
page in the web console. Supply the bucket and optional prefix, endpoint,
signing region, access mode, and credentials. Private credentials are sealed
with the instance key; include that key in the backup described above.

You can also index an existing, externally managed registry surface without
changing the producer that created it:

```sh
./result/bin/aos-hub --root /var/lib/aos-hub \
  registry add acme-cdn file:///var/lib/aos-hub/storage/registry-surface \
  --trust-key 'maintainer:Ed25519:<base64-public-key>'
```

The Hub verifies signed registry data and fails closed by default. Avoid
`--no-verify` outside deliberate inspection of untrusted data. For same-host
surfaces, use `file://`; production outbound HTTP rejects loopback, private,
link-local, and metadata addresses.

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
