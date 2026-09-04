# Trust an internal AOS Hub deployment

AOS Hub can host registry metadata, binary-cache objects, documentation, and
management APIs for an organization. It controls who may administer or publish
to those surfaces. APM package authenticity remains rooted in registry and TUF
release authorization plus the signed store graph. A cache signature is a
separate authority used by stock Nix clients.

This guide defines the trust boundaries for an internal native or Cloudflare
deployment. Use [Operate AOS Hub in production](production.md) for topology,
backup, monitoring, and upgrade procedures, and [Configure package
registries](../aos/registries.md) for client-side registry policy.

## Separate the Hub from release authority

The preferred internal deployment keeps signing authorities outside the Hub:

```text
reviewed publisher and external signers
  -> signed registry, TUF, narinfo, provenance, and release objects
  -> authenticated upload to AOS Hub
  -> Hub database indexes ownership and publication state
  -> object storage serves immutable bytes
  -> AOS clients verify signatures, freshness, and store identities
```

In this model, compromising the Hub, its database, or its object store may
expose private catalog visibility, corrupt or withhold bytes, change routing,
or disrupt availability. It must not let an attacker mint a trusted package,
release, cache entry, or bootable image.

The Hub supports sealed hosted signing material for workflows that explicitly
choose that convenience. That makes the Hub and its seal key part of the
affected registry's signing boundary. Do not use hosted private keys for the
canonical production roles, and do not describe such a registry as protected
from Hub compromise. Record which internal registries, if any, accept this
collapsed boundary.

## Keep the authorities distinct

| Authority | Purpose | Normal location |
| --- | --- | --- |
| Hub owner and organization roles | Manage accounts, registries, storage, routes, and policy | Hub database and identity provider |
| Provisioning or API token | Authorize a bounded Hub operation | External automation secret store; hash or session state in Hub |
| TLS key | Authenticate the Hub network endpoint | Reverse proxy, load balancer, or Cloudflare |
| Registry release signer | Authorize registry history, catalogs, and store graphs | Publisher or external signer outside Hub |
| Registry channel signers | Move partitions for one named channel to already authorized releases | Role-scoped publisher or external signer outside Hub |
| TUF roles | Authorize root evolution, delegated releases, snapshots, and freshness | Role-separated external signers |
| Cache signer | Authorize narinfo fingerprints | Cache release signer outside Hub |
| Secure Boot and PCR-policy roles | Authorize boot artifacts and sealed-state policy | Offline or hardware-backed release environment |
| Hub seal key | Encrypt Hub-stored credentials and optional hosted signing material | Native protected file or Cloudflare Worker secret |
| Hub JWT secret | Sign Hub bearer access tokens | Native runtime credential when configured; Cloudflare Worker secret |

Do not reuse a registry key as a Hub login, upload, SSH, TLS, or cache key. A
valid Hub token authorizes a write to the service; it does not authorize the
resulting bytes as a package release.

The table describes the canonical production boundary. The current preview TUF
implementation assigns its top-level roles to active registry keys; it does not
yet supply that isolation. An internal deployment using the preview path must
record the collapsed authority and must not claim production TUF role
separation.

## Bootstrap internal client trust independently

An internal registry's first public key must reach clients without depending on
that registry's unauthenticated response. The normal fleet paths are:

- bake the registry definition and public key into the AOS image; or
- deliver them through `host.nix` authenticated by an image-baked
  configuration key.

Configure the Hub URL, registry name, channel, and trust line together:

```nix
{
  aos.apm.registries.acme = {
    url = "https://hub.acme.example/acme/production/";
    channel = "stable";
    priority = 900;
    required = true;
    trustKeys = ["acme:Ed25519:BASE64_KEY"];
  };
}
```

The Hub's TLS certificate is a separate network identity. Fetching a registry
key over authenticated organizational TLS can be part of an operator ceremony,
but fleet automation should bind the reviewed key in image or signed
configuration policy rather than silently trust the first response.

## Design organization and registry ownership

Map each registry to one accountable organization and release policy. Hub
instance owners can administer the whole service; organization owners can
delegate narrower registry and publication roles. Minimize both and use scoped,
expiring automation tokens for routine work.

Do not use separate registries merely as environment labels when the same
owner, trust root, and dependency universe apply. Use signed release channels
for maturity and rollout. Create a separate registry when ownership, trust
root, legal policy, or dependency resolution must be independent.

Package names can override lower-priority registries on a client. An internal
organization registry that publishes a public package name therefore assumes
responsibility for that override. Registry ownership and client priority policy
must agree; Hub namespace separation alone cannot prevent an operator from
configuring an unsafe client override.

## Distinguish public and private registries

A public registry permits anonymous reads. A private registry requires Hub
authentication before returning protected metadata or objects. Both still
require cryptographic verification by APM.

Privacy and authenticity fail differently:

- a leaked read token may disclose private package names, versions,
  documentation, or binaries without allowing a valid release to be forged;
- a leaked upload token may alter the serving surface, but clients should
  reject unsigned or inconsistent objects;
- a leaked registry signing key may authorize malicious package metadata even
  when Hub access controls remain intact; and
- a leaked Hub seal key may expose stored provider credentials and any hosted
  signing material.

Use HTTPS whenever a bearer credential is present. Scope tokens to one
organization, registry, audience, and operation where supported, and set an
expiration appropriate to the job.

## Treat storage and delivery as untrusted transport

The native Hub may use local files or S3-compatible storage. The Worker uses R2
and may cache state in KV or at the edge. In every topology, clients must verify
the content rather than trust storage correctness.

Publication should:

1. validate the signed registry, store graph, cache, and release metadata;
2. write immutable NARs, images, Git objects, documentation, and metadata
   before mutable pointers;
3. use leases or compare-and-swap checks for channel movement;
4. read uploaded objects back through the public delivery route; and
5. record the exact object identities and publication result.

A CDN may serve stale bytes. TUF timestamp expiry, channel staleness policy,
name binding, and monotonic state limit stale moving references, while content
hashes and signatures detect altered immutable objects. An explicit immutable
release pin remains intentionally reproducible.

## Protect native deployments

Run the native service under its dedicated account, keep its listener private
behind TLS, and restrict filesystem and shell access to its SQLite database,
WAL files, `secret.key`, and storage bindings. Local `aos-hub --root ...`
commands bypass public HTTP authorization, so access to the host and state root
is instance-administrator authority.

The instance seal key protects stored credentials and optional hosted signing
material. Back it up with the database and storage recovery point. Losing it
makes sealed values unreadable; exposing it may disclose them.

Without a configured native JWT credential, access-token signing keys are
ephemeral and existing short-lived tokens stop working after restart. When the
AOS service supplies `credentials.jwtSecret`, preserve and rotate that runtime
credential deliberately instead of relying on restart invalidation.

The native service does not currently trust forwarded client-address headers.
Behind a proxy, pre-authentication rate limiting sees the proxy peer. Enforce
per-client edge policy at a trusted proxy rather than accepting arbitrary
forwarding headers.

See [Deploy AOS Hub as a native service](native.md) for initialization,
credentials, storage bindings, and backup details.

## Protect Cloudflare deployments

The Worker system of record is Durable Object SQLite; registry and cache bytes
live in R2, and KV holds session and hot state. Protect the Cloudflare account,
deployment token, runtime API token, `HUB_SEAL_KEY`, and `HUB_JWT_SECRET` as
separate authorities.

`HUB_SEAL_KEY` is recovery-critical. Replacing it without migrating sealed
data can make OIDC credentials, storage credentials, and hosted signing keys
unreadable. Rotating `HUB_JWT_SECRET` intentionally invalidates issued access
tokens. Routine deploys must preserve both unless executing a reviewed rotation
or recovery.

Provider account recovery, Durable Object export, R2 retention, KV state,
domains, Worker configuration, secrets, and log destinations are all part of
the deployment recovery plan. The packaged installer deploys and migrates the
application; it is not a provider backup system.

See [Deploy AOS Hub to Cloudflare](cloudflare.md) for resource and deployment
details.

## Authenticate administrators and automation

Use invite-only signup for organizational instances until a reviewed identity
policy says otherwise. Prefer OIDC with explicit issuer, audience, group-to-
role mapping, and a tested local owner recovery path. Verify time, TLS,
identity-provider failure behavior, and removal of former administrators.

Provisioning tokens should be printed once, stored immediately, scoped to the
smallest useful resource and permission, and exchanged for ordinary access
tokens. Publishing package objects does not require instance ownership.

Separate staging and production identities, storage, tokens, domains, and
deployment state. Promotion should move the exact qualified bytes; it must not
rebuild or re-sign them inside production Hub.

## Back up and restore the trust boundary

A useful recovery point contains more than the database:

- the Hub database and its consistent journal state;
- the native seal key or the Worker secret configuration;
- registry and cache objects at the corresponding publication generation;
- storage bindings, routes, domains, and identity-provider configuration;
- externally managed trust keys and release evidence; and
- the accounts and credentials needed to reach the recovery environment.

Restore into an isolated namespace first. Verify sign-in, private reads,
registry indexing, package publication, cache downloads, signed-object
validation, and client consumption. A database query alone does not prove that
object storage, sealed credentials, or delivery routes survived.

## Respond according to the incident

| Incident | First actions |
| --- | --- |
| Hub access token exposed | Revoke the token, inspect audit state, and verify every affected publication object |
| Hub owner or IdP compromised | Disable affected identities, preserve database and provider logs, and review all topology and policy changes |
| Object storage altered | Freeze publication, compare with signed release evidence, restore immutable objects, and verify them through the public route |
| Seal key exposed | Treat every sealed credential and hosted signing key as exposed; rotate or replace them and reseal under a new key |
| Registry release signer exposed | Stop that registry's releases, revoke Hub upload access, and follow registry key-compromise recovery |
| Registry channel signer exposed | Freeze the affected channel, rotate its scoped key, and verify that no unauthorized release content was accepted |
| TLS key exposed | Replace the endpoint certificate and key; independently verify registry signatures throughout the transition |
| Database lost or corrupt | Stop writers, restore a consistent database plus storage point, and verify client-visible signed state before reopening writes |

Do not disable registry verification to restore service. Hub availability and
package authenticity are separate recovery goals; restore both without using a
failure in one to waive the other.

## Verify the deployed boundary

For either topology, exercise:

- anonymous public reads and authenticated private reads;
- denial for expired, wrong-scope, and cross-organization tokens;
- a signed publication and rejection of altered or unsigned content;
- read-back through the configured CDN or public route;
- client verification from a clean AOS trust seed;
- backup restoration in an isolated deployment; and
- audit and alert delivery for failed publication or authentication.

Health endpoints, database availability, or a successful browser login do not
prove package trust. Include a real signed registry and NAR verification in the
deployment acceptance test.
