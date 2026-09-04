# Deploy AOS Hub as a native service

The native server keeps its system of record in SQLite and serves registry and
cache bytes from local or S3-compatible storage. Put it behind a TLS reverse
proxy for internet-facing use.

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

The service does not terminate TLS. Configure a reverse proxy to send the
public HTTPS origin to `127.0.0.1:8420` and preserve the request host. The
native server does not yet trust forwarded client addresses, so pre-auth rate
limits behind a proxy apply to the proxy peer rather than individual clients.

## Understand the state

Stop the Hub and back up the complete state root. It contains:

- `/var/lib/aos-hub/hub.db` and any SQLite WAL files;
- `/var/lib/aos-hub/secret.key`, used to seal stored credentials and hosted
  signing-key material;
- local filesystem bindings placed beneath the state root.

The secret key is created with mode `0600` on first production use. It may also
be supplied from a protected file through `AOS_HUB_SECRET_KEY_FILE`. Losing it
makes sealed values unusable.

When `AOS_HUB_SECRET_KEY_FILE` points outside the Hub state root, back up that
external key file with the same recovery point.

Copy the complete stopped state root as one recovery point. If registry or cache
bindings live elsewhere, include those paths as well. Include the reverse-proxy
and service configuration in the same backup plan. Use SQLite's online-backup
mechanism instead if the service cannot be stopped.

Without a configured JWT credential, access-token signing keys are regenerated
when the native process starts. Existing one-hour API access tokens then stop
working after a restart; exchange the durable provisioning token again. When
the AOS service supplies `credentials.jwtSecret`, preserve that runtime
credential with the deployment's secret state.

## Add registry storage

Managed registries use named bindings. The simplest native binding is
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
