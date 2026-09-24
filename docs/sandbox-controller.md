# Sandbox controller endpoints

The packaged controller publishes broker inventory and exposes discovery,
authorized resource and operation reads, watch, and public mutation admission.
Some admitted mutations still lack a completing production effect. Controller
readiness confirms its initial authenticated catalog cycle, not completion of
RFC-0021 or readiness to run every sandbox feature.

## Registered TLS public API

The optional endpoint is `/run/aos/sandboxd/public.sock`. It carries TLS 1.3
with mandatory client certificates and HTTP/2 ALPN; it is not a plaintext Unix
HTTP endpoint. Discovery, Sandbox, Execution, FilesystemView, Snapshot,
Capability, Cache, Operator, and Operation services are registered there,
including `CancelOperation` and `Watch`. Registration does not establish that
each admitted mutation has a terminal effect. The existing `diagnostics.sock`
remains restricted to root by kernel peer credentials.

After configuring the controller, its node identity, and all four broker
sessions, enable the public endpoint with external system credentials:

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
rechecks the registered peer before and after each public handler.

`CapabilityService/Bootstrap` can issue the first holder handle only when two
additional external credentials are installed together:

| Fixed credential | Contents |
| --- | --- |
| `public-api-entitlements` | Signed canonical version-1 JSON document |
| `public-api-entitlement-public-key` | Dedicated 32-byte Ed25519 verifier |

Configure them as `credentials.publicApiEntitlements` and
`credentials.publicApiEntitlementPublicKey`. The signing key stays outside the
controller and repository. Without both credentials, bootstrap rejects every
request while the other registered public methods remain available.

The document contains `version: 1`, a nonzero `generation`, a sorted nonempty
`entries` array, and a 64-byte `signature`. Each entry binds an exact principal,
project, registered certificate-key binding, current policy digest and
generation, controller generation, project revocation scope and generation,
validity interval, bounded lifetime, grants, and delegation limits. Ed25519
signs the domain-separated compact JSON of `version`, `generation`, and
`entries`; the complete JSON must be canonical. A request contains only a
16–128 byte idempotency key. The controller reads the fixed credentials afresh,
checks the live TLS peer and every protected current head, then atomically
commits a V3 capability, opaque handle, holder-specific replay decision, and
entitlement generation floor. Exact replay returns the same handle while it
remains current. A different idempotency key, changed entitlement, revoked or
expired capability, or stale peer is rejected. Handles are returned only on
the authenticated response and never enter a public projection or audit event.

An offline administrator creates the credentials with
`aos-sandbox-entitlement-sign UNSIGNED_JSON PRIVATE_SEED_32B SIGNED_JSON_OUT PUBLIC_KEY_32B_OUT`.
The unsigned JSON has exactly `version`, `generation`, and `entries`; the tool
validates and canonicalizes it, then round-trips the signed result through the
production verifier. The Ed25519 seed is exactly 32 raw bytes in a private
regular file (no group/other permission bits). Both output files are created
exclusively with mode `0600`, never overwritten. Provision the signed JSON and
public-key bytes as the fixed credentials above, and keep the seed offline and
outside the repository and Nix store. Increase `generation` when rotating the
document; a lower generation, or different document at the same generation,
fails closed after a bootstrap decision has been committed.

`GetOperation` additionally requires `aos-capability-id` containing one
canonical lowercase, hyphenated, nonzero capability UUID. This value is only a
lookup key: the controller loads the current protected capability, policy,
revocation head, and clock state, then binds them to the registered principal,
project, certificate key, live TLS exporter, exact RPC method, exact protobuf
request bytes, and the operation's immutable admitted project/resource
selector. Authority is rechecked for every read. Missing, legacy, cross-project,
revoked, expired, or insufficiently authorized operation observations are
concealed as not found; malformed or missing capability identities are rejected
as unauthenticated. Root diagnostics may still inspect legacy observations.

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

The packaged CLI and direct registered clients can use public reads, watch,
and mutation admission through this endpoint. `CacheUnpin` has a completing
controller effect. `CachePin` can cold-recover an existing protected acquisition,
but fresh pins and `ExecutionControl` still admit without completing effects;
other effect paths require their own production and qualification checks.
Do not infer operation completion from an accepted mutation response.

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
identity, and its client certificate.

An authorized public operation read additionally requires
`sandbox-capability-id` in the same directory. It is an exact canonical
lowercase hyphenated UUID with no trailing newline, stored as a user-owned,
single-link mode-0600 regular file. The value is sent as the
`aos-capability-id` lookup header; it is not bearer authority. For example,
where the operation argument is its 16-byte lowercase hexadecimal identity:

```text
aos sandbox \
  --public-api \
  --public-server-name sandbox-controller.example \
  --public-credentials /absolute/private/credential-directory \
  get --resource operation 00112233445566778899aabbccddeeff
```

Without `--public-api`, the same `get --resource operation` command uses the
root-only diagnostic socket and does not load a capability credential. These
options select the registered public endpoint; they do not turn an admitted
but unfinished effect path into a completed operation.
