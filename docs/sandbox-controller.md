# Sandbox controller endpoints

The packaged controller currently publishes broker inventory and exposes
discovery. It does not yet admit or execute public mutations. Controller
readiness confirms its initial authenticated catalog cycle, not completion of
RFC-0021 or readiness to run sandboxes.

## Registered TLS discovery

The optional endpoint is `/run/aos/sandboxd/public.sock`. It carries TLS 1.3
with mandatory client certificates and HTTP/2 ALPN; it is not a plaintext Unix
HTTP endpoint. Only `DiscoveryService` is registered there. The existing
`diagnostics.sock` remains restricted to root by kernel peer credentials.

After configuring the controller, its node identity, and all four broker
sessions, enable public discovery with external system credentials:

```nix
aos.sandbox.controllerService = {
  publicApi.enable = true;
  credentials = {
    publicApiServerCert = "sandbox-api-server-cert";
    publicApiServerKey = "sandbox-api-server-key";
    publicApiClientCa = "sandbox-api-client-ca";
    publicApiPrincipals = "sandbox-api-principals";
  };
};
```

These values name credentials supplied under `/run/credentials/@system/`;
they are not paths to repository files or Nix-store secrets. Provision private
keys outside the repository and store. systemd loads them into the service's
private credential directory using these fixed names:

| Fixed credential | Contents |
| --- | --- |
| `public-api-server-cert` | PEM server certificate chain |
| `public-api-server-key` | Matching PEM private key |
| `public-api-client-ca` | PEM client trust anchors |
| `public-api-principals` | Closed version-1 JSON registration document |

The registration document has `version: 1` and a nonempty `peers` array. Each
entry has exactly `certificate_sha256`, `principal`, and `project`.
`certificate_sha256` is the SHA-256 digest of the client's leaf certificate
DER, encoded as an array of exactly 32 byte integers. Principal and project
are nonzero canonical lowercase hyphenated UUID strings. Duplicate certificate
digests, unknown fields, and more than 4,096 entries are rejected. Each
credential is limited to 1 MiB.

Registration identifies a client; it grants no capability or mutation
authority. A trusted certificate without an exact registration is rejected.
Request identity headers cannot replace connection metadata. The service
rechecks the registered peer before and after each discovery handler.

## Activation and rotation

Enabling the endpoint requires all four credentials. Invalid credential
custody or content fails startup before readiness. The endpoint admits at most
32 connections and eight concurrent handshakes. Handshakes have a ten-second
budget; peer authorization has a five-minute BOOTTIME lifetime. Pending I/O
also has expiry wake-ups, and every I/O poll checks BOOTTIME.

Credential changes invalidate retained peer evidence. Once a peer fails a
currentness check, that connection remains retired even if the original
credential bytes are restored; authentication requires a new TLS session.
The acceptor does not hot-reload credentials: install replacements through the
external credential mechanism and restart the controller. Before restarting,
reconcile pending protected broker-session history; never erase its journal to
bypass recovery.

The public endpoint has no mutation handlers; CLI integration is discovery-only.
The service-UID VM qualification exercises protected credential loading,
registered and rejected TLS clients, real HTTP/2 discovery, credential
rotation, and permanent retirement of stale peer evidence. Installed systemd
activation and restart recovery still require qualification. See the
[production integration audit](rfcs/0021-sandbox-runtime/16-implementation-tasks.md#production-integration-audit)
for the remaining work.

The packaged CLI can use the registered-client endpoint for either discovery
command:

```text
aos sandbox \
  --public-api \
  --public-server-name sandbox-controller.example \
  --public-credentials /absolute/private/credential-directory \
  capabilities public-api
```

The credential directory must be user-owned with no group or other permissions
and reached only through root- or user-owned ancestors that are not group- or
world-writable. It contains `sandbox-server-ca`, `sandbox-client-cert`, and
`sandbox-client-key`. Each must be a nonempty, user-owned, single-link regular
file; symlinks and files larger than 1 MiB are rejected. The CA and certificate
must not be group- or world-writable, and the key must have no group or other
permissions. The client requires TLS 1.3, HTTP/2, the configured server
identity, and its client certificate. These options do not activate mutation
routes that the controller has not registered.
