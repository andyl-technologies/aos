# Security and key architecture

## Threat model

The pipeline assumes any one of these may fail or be compromised independently:

- the public network, DNS, CDN, Hub Worker, Hub database, or object storage;
- a staging credential or staging environment;
- a production upload credential;
- the registry authoring clone or an interrupted publisher;
- the designated maintainer host while it is online;
- one removable key device or one active signing key;
- a package source, build input, converter, or cached build output; or
- a release operator account.

The design does not claim to survive simultaneous compromise of the maintainer
host, enough offline signing authorities to meet a threshold, and the human
review path. It also cannot make one physical maintainer host an independent
build service.

The security objective is that compromise of an online delivery component can
deny service or replay bounded stale data, but cannot create new trusted package
contents or bootable images. Compromise of an online channel or timestamp key
may select or refresh only metadata already authorized by offline release roles.

## Key roles

Private keys are separate even when two roles use the same algorithm.

| Role | Recommended custody | Quorum | Permitted operation |
| --- | --- | ---: | --- |
| Firmware PK | Offline hardware token, geographically backed up | Procedural two-person approval | Replace KEK authority or re-own a platform |
| Firmware KEK | Offline hardware token | Procedural two-person approval | Authorize db/dbx updates |
| Secure Boot db | Non-exportable HSM or hardware token | Two-person release approval | Authenticode-sign reviewed systemd-boot and normal/recovery UKIs |
| Module signing | Non-exportable HSM or hardware token | Two-person release approval | Sign modules for the production kernel certificate only |
| PCR policy | Non-exportable HSM or hardware token | Two-person release approval | Sign declared PCR policies embedded in reviewed UKIs |
| TUF root | Three offline Ed25519 devices in distinct custody | 2 of 3 | Authorize TUF role keys and root rotation |
| TUF top-level targets/delegations | Three offline Ed25519 devices | 2 of 3 | Authorize the release-role keys, paths, and thresholds |
| TUF stable release | Three offline Ed25519 devices in distinct custody | 2 of 3 | Authorize a stable-eligible or emergency release manifest |
| TUF candidate release | Two operator-present hardware devices | 1 of 2 | Authorize an RC manifest that stable cannot select |
| TUF edge release | TPM-sealed maintainer-host service key | 1 of 1 | Authorize only an edge-version manifest under the edge path |
| TUF snapshot | Separate TPM-sealed maintainer-host service key | 1 of 1 | Bind one set of already-authorized role metadata |
| TUF timestamp | TPM-sealed maintainer-host service key or restricted hardware token | 1 of 1 | Refresh a short-lived pointer to an existing snapshot |
| Registry Git commit/tag | Hardware-backed Ed25519 maintainer key | 1 signature, backed by TUF threshold | Preserve Git-native continuity and name binding |
| Registry stable channel | Dedicated hardware-backed Ed25519 key | 1 signature | Point stable partitions only to stable-authorized releases |
| Registry candidate/edge channels | Separate TPM-sealed maintainer-host keys | 1 signature | Point only the named channel to a release class it permits |
| Nix narinfo | Non-exportable cache Ed25519 key | 1 signature | Sign narinfos for manifest-listed NARs only |
| Release evidence | Maintainer-host TPM-backed Ed25519 key | 1 signature | Bind the public evidence manifest and threshold-authorize the completion journal head |
| Qualification authority | Dedicated TPM-backed Ed25519 key | 1 signature | Authorize one complete passing native gate matrix over exact staging bytes |
| Hub upload | Short-lived scoped bearer/capability | One release and environment | Upload manifest-listed objects; never sign content |
| Hub runtime/seal/JWT | Environment-local secret manager | Per environment | Run one Hub; never authorize AOS artifacts |

Firmware compatibility decides whether a device class uses RSA-3072 or a
documented RSA-2048/SHA-256 compatibility profile for UEFI keys. The choice is
qualified on that hardware class and recorded in the release manifest. It is
never silently weakened during signing.

Every boot-signing request also binds the exact target platform, PE machine
type, system variant, release, and unsigned artifact digest. A signature issued
for one Linux architecture cannot satisfy the other architecture's manifest.

No production release depends on a private key stored as an ordinary file on
the maintainer host. Encrypted offline backups are exception copies under
separate custody, not routine signing sources.

## TUF corrections required for production

The current AOS-TUF implementation supplies signed root, targets, snapshot, and
timestamp envelopes, version floors, expiry, hash binding, threshold checking,
and root-transition verification. It is not yet the production role model:

- all four roles are assigned the same active registry keys;
- `apr release` attempts to sign every role in one process;
- thresholds are derived from locally available active keys rather than an
  independently managed policy; and
- delegated, path-constrained release roles are absent; and
- `timestamp.json` is committed inside an immutable release, so its 14-day
  expiry cannot be refreshed without cutting a new release.

Production separates the roles in accordance with the
[TUF specification](https://theupdateframework.github.io/specification/latest/):

1. Bootstrap images carry a threshold-authenticated TUF root in addition to the
   registry Git continuity anchor.
2. Root policy explicitly assigns distinct key ids and thresholds to root,
   top-level targets, snapshot, and timestamp. Top-level targets delegates
   disjoint release paths and version classes to stable, candidate, and edge
   roles.
3. Root, top-level targets, and stable release private keys remain offline.
   Root rotation is signed by the old and new thresholds and publishes every
   intermediate root version.
4. The stable role threshold-authorizes stable-eligible and emergency release
   manifests. Candidate and edge roles cannot write that path or produce a
   version class that the stable channel accepts. The final no-suffix release
   appears on `candidate` with stable authorization before its soak begins.
5. Candidate and edge roles bind only their closed release manifests. Their
   compromise cannot alter the stable role, authorize stable content, or move
   a channel.
6. Snapshot is an online, separately keyed role that binds only metadata
   already authorized by the delegated release roles. It cannot add a target.
7. Timestamp is a small mutable object outside the immutable Git release tree.
   It expires after 48 hours and is renewed at least every 12 hours by the
   maintainer host.
8. The timestamp signer may only sign an already-authorized snapshot digest and
   monotonically increasing timestamp version. It cannot introduce targets,
   roots, Git commits, release tags, packages, images, or channel targets.
9. Moving-ref consumers require an unexpired timestamp and persist all metadata
   version floors. Explicit immutable release pins remain reproducible under
   the documented expiry policy.
10. Channel verification is role-aware: `stable` accepts only stable-authorized
    releases, `candidate` accepts candidate- or stable-authorized releases, and
    `edge` accepts any valid release class. Each channel key is confined to its
    named channel and cannot create release content.
11. Registry and channel signatures remain defense in depth and continuity
    mechanisms. TUF role policy is the final authorization for release content.

Role separation must be enforced by parsers and signers, not by filenames and
operator convention alone. A key request includes a domain-separated role,
registry id, release id, metadata version, and payload digest. A signing device
or service refuses all other purposes.

## Secure Boot production finalization

The checked-in `server-secureboot`, `server-secureboot-lockdown`,
`server-measured-boot`, and derived verity variants use public test keys. The
current module passes private-key paths into Nix builds and can copy that
material into a store closure. That path remains restricted to tests and
controlled experiments.

The production path is a two-stage build:

```text
hermetic Nix build                         external finalizer
------------------                        ------------------
unsigned modules + embedded public cert -> hardware-sign modules
unsigned UKIs + PCR calculation inputs   -> hardware-sign PCR policy and PE
unsigned systemd-boot                     -> hardware-sign PE
root/verity/layout inputs                 -> assemble final A/B disk
conversion tools + declared parameters   -> raw/qcow2/vmdk/vhd
                                              |
                                              v
                                     verify and content-address
```

`ukify` supports passing private-key URIs through an OpenSSL engine or provider,
which is the required abstraction boundary; see the
[`ukify` manual](https://www.freedesktop.org/software/systemd/man/latest/ukify.html).
The AOS finalizer additionally needs provider-backed module signing and
Nix-cache signing. A file-path fallback is permitted only for explicitly
marked test keys inside an isolated test store.

The finalizer is deterministic except for signature encoding and declared
signing time. It records both the unsigned input digest and finalized output
digest. It reads a closed manifest, creates outputs in a new directory, and
cannot modify the source checkout or unsigned build output.

Post-sign verification uses public material and independent parsers. It checks:

- every module signature and the kernel's embedded certificate;
- Authenticode on systemd-boot, slot A/B UKIs, and recovery UKIs against an
  active db certificate;
- SBAT component/generation policy and planned revocation floor;
- PCR signature, public key, measured sections, and final ready-phase PCR 11;
- dm-verity root/hash-tree agreement and full-device read;
- recovery manifest and detached signature over all required components;
- exact UKI copies embedded in every disk encoding; and
- conversion round-trip identity with the finalized logical raw disk.

The Secure Boot db key is not the registry, TUF, cache, or provenance key. A
compromised Hub or registry signer therefore cannot mint firmware-trusted code.

## Production image security profile

A published production image must have a non-fixture system definition whose
evaluation asserts all applicable controls:

- UEFI Secure Boot with deployment-owned PK, KEK, db, and authenticated
  enrollment/update artifacts;
- kernel lockdown in confidentiality mode, forced module signatures, and
  signed kexec;
- measured boot with a hardware-backed PCR-policy signature;
- TPM2-sealed LUKS2 `/var`, pinned Secure Boot/external-input PCRs, and a tested
  off-host recovery-secret escrow acknowledgement;
- EROFS immutable root and complete dm-verity verification before persistent
  state is exposed;
- signed A/B normal and recovery UKIs, boot counting, rollback, and removable
  recovery media;
- the repository's hardened sysctl/kernel profile, audit, default-deny
  firewall, no core dumps, and no test artifacts;
- signed registry, NAR, package realization, image catalog, source,
  documentation, and host-configuration inputs;
- complete closure/source/license SBOM evidence and a release-policy decision
  over a pinned, authenticated vulnerability snapshot; and
- the supported MAC policy in enforcing mode once its actual production policy
  package and labeled-root behavior pass their release gate.

Today `aos.security.level = "hardened"` still disables SELinux because the
production policy is not complete. The release profile must not claim SELinux
enforcement until that gap is implemented and tested. Security readiness is
defined by enforced, observed controls, not by setting every available option
or by wording in a profile name.

UEFI Setup Mode is not an acceptable steady state. Production appliances use
pre-enrollment where supported. A hardware class that requires Setup Mode uses
an offline, physically controlled enrollment ceremony with networking and
untrusted storage unavailable, verifies PK/KEK/db afterward, enables firmware
administrative protection, and reaches Secure Boot enforcement before any
persistent secrets or production workload are introduced.

db rotation is additive first: deploy the new certificate, prove fleet and
recovery coverage, switch signers, then distribute a KEK-authorized dbx/SBAT
revocation only after the old-key recovery plan is no longer needed. TPM and
storage recovery secrets are escrowed and restore-tested before a release can
advance beyond internal canaries.

The vulnerability gate is reproducible: the scanner and advisory snapshot are
declared inputs and their digests appear in the release evidence. Stable has no
unreviewed critical or high finding. An accepted exception names the affected
component, exploitability analysis, compensating control, owner, expiry, and
correcting release; it is signed as release evidence and is never a silent
scanner suppression.

## Hub and delivery security

Staging and production use distinct Workers, Durable Object state, R2 buckets,
KV namespaces, Queues, rate-limit namespaces, route reservations, JWT secrets,
seal keys, runtime Cloudflare tokens, upload credentials, identities, and audit
streams. A staging token is structurally unable to address production storage.

Production publication requires:

- TLS on every public route, HSTS after route qualification, and no HTTP
  downgrade;
- exact host/path routing and the RFC-0012 network-policy observations;
- short-lived least-privilege upload grants bound to one bundle digest;
- multi-factor operator authentication and a separate break-glass owner whose
  credential is tested and otherwise offline;
- compare-and-swap publication generations and one active writer;
- immutable object retention plus protected mutable refs;
- audit logs for authentication, token minting, publication, route, key,
  retention, GC, and administrative changes;
- encrypted, restorable backups of the Hub system of record, sealing material,
  provider configuration, and object storage; and
- public probes from outside the provider path.

The Hub may store transport or environment-local signing material sealed under
its environment seal key, but it must not hold the production TUF root/targets,
Secure Boot, module, PCR-policy, Nix-cache, or release-evidence private keys.

## Maintainer host and provenance

The designated maintainer machine is both workstation and build coordinator for
this phase. It is a single point of build trust, so it is hardened and its
authority is narrowed:

- measured and verified boot, encrypted local storage, current firmware and
  operating system, TPM-backed host identity, and recorded boot state;
- dedicated unprivileged release and timestamp-service identities;
- hardware-backed SSH and Hub operator authentication;
- no inbound services beyond explicitly administered access; default-deny
  firewall and restricted release-time egress;
- sandboxed Nix daemon, no untrusted binary substituters, and no host-tool
  fallback;
- separate clean source, authoring, unsigned-build, finalized, evidence, and
  secret-mount locations with least privilege;
- removable signing devices absent except during a ceremony;
- no production secret in shell history, environment, repository, Nix store,
  derivation, log, crash dump, swap, or release bundle; and
- encrypted backups and a tested host rebuild from documented public inputs.

The pipeline emits SLSA-shaped build provenance identifying artifact digests,
source, builder, build process, and inputs. This satisfies the useful inventory
goal described by [SLSA provenance](https://slsa.dev/spec/v1.2/provenance), but
a maintainer-controlled workstation does not satisfy the hosted build-platform
requirements for SLSA Build L2 or the hardened isolation requirements for L3.
The public record therefore declares `build_level = 1` until a qualifying
independent build service exists. Two builds on the same maintainer host are
nondeterminism evidence, not independent corroboration.

## Rotation and compromise

Every key has an owner, creation time, activation time, expiry or review date,
public fingerprint, allowed role, storage device id, backup status, last-use
record, rotation successor, and compromise procedure. The inventory contains no
private material.

Planned rotations overlap old and new public authorities for at least one
stable image and one complete stable rollout. Rotation exercises happen before
expiry, not during it. TUF root transitions publish every intermediate root;
registry roster transitions preserve Git continuity; db transitions preserve
boot and recovery coverage.

On suspected compromise:

1. Freeze signing, publication, timestamp refresh, and channel advancement.
2. Revoke Hub and provider credentials and isolate the maintainer host as
   appropriate.
3. Preserve public objects, logs, journals, key-device audit data, and the last
   known-good roots and channel maps.
4. Determine the compromised role and its maximum authority.
5. Use an uncompromised threshold or the documented out-of-band bootstrap path
   to rotate; never let a sole compromised key self-revoke.
6. Publish a higher fix-forward release and new freshness metadata.
7. Re-establish trust from a clean consumer and verified-boot canary before
   resuming partitions.

Loss and compromise are different. Loss uses an authenticated backup or
surviving threshold. Compromise also invalidates everything the key could have
authorized since the last known-good audit point and requires an incident
release.
