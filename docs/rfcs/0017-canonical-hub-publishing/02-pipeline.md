# Canonical publishing pipeline

## Release unit

The release unit is a closed, content-addressed bundle. It contains every
artifact that may be published and enough signed evidence to decide whether
those bytes may cross each state transition.

At minimum the bundle inventories:

- source commit, source tree digest, signed source-release reference, and the
  complete authorized-contributor check result;
- evaluated AOS system and package-set identities;
- Nix derivations, output paths, NAR hashes, closure edges, and cache narinfos;
- registry Git commit, release tag, channel-independent TUF metadata, package
  catalog, documentation objects, and store realization graph;
- source outputs and license-boundary reports, including matching patched-QEMU
  corresponding source when applicable;
- a machine-readable software bill of materials covering every store path,
  source archive, version, dependency edge, license expression, and output
  digest in the published closure;
- the signed, timestamped vulnerability/advisory input and the disposition of
  every finding applicable to the release;
- unsigned build products and their repeat-build comparison;
- finalized signed UKIs, bootloader, modules, PCR policy, recovery bundle, raw
  logical disk, converted images, and `image-info.json` where applicable;
- SHA-256, size, media type, compression, platform, and logical relationship
  for every published file;
- signing key ids, certificate fingerprints, signature verification results,
  SBAT generations, dm-verity roots, and expected PCR values;
- gate names, exact commands, result store paths, start and finish times, and
  logs or digests of logs;
- staging upload receipt and public read-back results;
- production upload receipt, channel plan, channel observations, approvals,
  and incident/waiver references; and
- the release-tool and Hub deployment ids used for every transition.

The public portion is signed by the provenance/evidence key and published with
the release. Secrets, personal data, provider account ids, internal host
addresses, and raw logs remain in the restricted operator record; the public
manifest carries their digests and pass/fail claims.

## States

One release id advances monotonically through this state machine:

```text
planned -> built -> finalized -> staged -> qualified -> promoted -> rolling -> complete
    |         |          |          |          |           |          |
    +---------+----------+----------+----------+-----------+----------+-> failed
```

`failed` is terminal for the release bytes. A failed version is never reused.
An interrupted transition may resume only from a verified journal whose inputs
and already-written immutable objects match the bundle manifest.

### `planned`

The release plan freezes:

- release version and class (`edge`, `candidate`, `stable-eligible`, or
  `emergency`);
- exact source commit, target channels, and intended partition changes;
- package, image, documentation, source, and license artifact matrix;
- build and signing tool closures;
- mandatory gates selected from the changed paths and release class;
- expected staging and production Hub deployment ids;
- key ids and quorum policy, without private material; and
- retention roots and rollback/fix-forward owner.

The planner rejects a dirty checkout, a commit not reachable from protected
`origin/master`, a reused version, a non-fast-forward registry base, missing
contribution authorization, or an unknown current public channel state.

### `built`

The designated maintainer host performs a hermetic, sandboxed build without
release private keys. The source checkout and registry authoring clone are
separate. The release job captures the derivation graph before realizing
artifacts and verifies that no nixpkgs or host-tool dependency enters it.

Release builds run twice from the same declared inputs, forcing independent
realization rather than accepting an existing output as the second build. NAR
hashes and unsigned image contents must match. A same-host repeat build detects
nondeterminism but is not called independent reproducibility and does not prove
the maintainer host is uncompromised.

All applicable repository checks run before finalization. The baseline includes:

- `checks.eval` and formatting/lint/documentation checks;
- the complete package and closure validation selected by the change;
- secret scanning, source/license inventory, SBOM completeness, and
  vulnerability-policy evaluation against a pinned advisory snapshot;
- every discovered image-budget check for a published system;
- `checks.fleet.apr-release-e2e` and the Hub/APM publication path;
- install-from-image, Secure Boot, lockdown, measured-boot, registry Secure
  Boot catalog, signed package-root image, and image rollback checks for an
  image-bearing release;
- provisioning and on-host configuration gates when their inputs change; and
- `gate:abi-conformance`, `gate:license-boundary`, and corresponding-source
  retention whenever the Crucible/QEMU boundary is in the published closure.

The planner resolves exact attribute names against the source commit rather
than relying on a stale hard-coded command list.

### `finalized`

External signing consumes only the frozen unsigned manifest and produces a new
final manifest. The signer verifies the release id, source commit, artifact
digests, key role, requested signature purpose, and operator approval before it
uses a key.

For an image-bearing release, finalization:

1. Signs modules with the module key and verifies every signature against the
   certificate embedded in the kernel.
2. Calculates the declared PCR policy and signs it with the PCR-policy key.
3. Assembles and signs normal and recovery UKIs and systemd-boot with the
   Secure Boot db key.
4. Reconstructs the A/B disk and recovery bundle from those finalized bytes.
5. Derives raw, QCOW2, VMDK, and VHD delivery encodings deterministically.
6. Recomputes `image-info.json`, delivery hashes, UKI identities, SBAT facts,
   dm-verity roots, recovery manifest, and expected PCR measurements from the
   result rather than copying claims from the request.
7. Independently verifies Authenticode, module signatures, PCR policy,
   recovery signatures, disk layout, and conversion round trips.
8. Imports finalized content into content-addressed Nix store paths without
   making the private key or signing service a derivation input.

Registry finalization then records the resulting store paths, source and
documentation objects, image facts, and recovery artifacts; constructs the
immutable release; creates threshold release metadata; signs narinfos; and
writes the release evidence envelope. No channel moves in this state.

### `staged`

The maintainer host obtains a short-lived, staging-only upload grant. It uploads
immutable objects first and mutable registry discovery data last to the
isolated staging Hub. The Hub verifies the bundle signature, expected staging
deployment id, registry identity, object hashes, sizes, completeness, and
compare-and-swap base before it admits the publication.

Read-back is from `aos.staging.andyl.org`, not from the local authoring clone or
provider storage endpoint. Every object is fetched by its public route and
compared with the manifest. Range requests are checked for image artifacts.

Staging registry metadata may refer to the canonical production cache URL. A
staging APM test uses an explicit staging cache override until the immutable
objects are present in production. Environment-specific cache URLs must not be
baked into the release commit merely to make staging work.

### `qualified`

Qualification boots and exercises the exact finalized bytes read back from the
staging Hub. It must not substitute a local image or regenerate a metadata file.

An image-bearing candidate passes:

- SHA-256, size, catalog signature, TUF threshold, narinfo, realization graph,
  source/license, Secure Boot certificate, SBAT, and recovery-manifest checks;
- raw decompression and conversion back to the same logical disk;
- UEFI boot with Secure Boot enforcing, kernel lockdown active, expected
  dm-verity root, TPM-backed `/var` unlock, signed PCR policy, and no failed
  units;
- authenticated provisioning, signed host configuration, registry update,
  package activation, reboot, and generation quote verification;
- A/B image update, boot blessing, forced candidate failure, automatic
  fallback, and offline recovery media;
- the platform-specific canary appropriate to every advertised format; and
- clean Hub logs, storage checks, ranged downloads, cache headers, and audit
  entries.

A package-only candidate installs and activates each changed package in its
supported system context, verifies package-root integrity and documentation,
proves no image-affecting input changed, and has no unreviewed finding that
violates the channel policy. A Hub Worker release follows the separate
application path below.

### `promoted`

Promotion copies the bundle's existing immutable objects to production storage
and imports its existing signed registry objects. It never invokes Nix,
`ukify`, an image converter, a signing key, or a metadata generator.

The production Hub requires:

- a short-lived token scoped to `andyl/main` publication;
- the exact qualified bundle id and staging receipt;
- a production deployment id on the release plan's allowlist;
- object-by-object digest and completeness verification;
- a current backup and restore proof within policy;
- a compare-and-swap base matching the recorded production generation; and
- no active publication or topology migration.

Production immutable objects are uploaded first. The registry snapshot becomes
discoverable only after every referenced cache, image, documentation, source,
and recovery object is readable and verified. A clean consumer with only the
image-baked trust root must verify the candidate from the public production
route before any supported channel changes.

### `rolling` and `complete`

`edge` and `candidate` advance all partitions after production read-back. An
image-bearing candidate therefore imports its qualified image objects before
the candidate pointer moves. A normal stable release reuses those production
objects, advances the four recorded canary partitions, observes the ring, and
proceeds through the cumulative `4 -> 32 -> 128 -> 256` plan.

Each advancement is an independent, signed, compare-and-swap operation. The
operator records:

- expected old release per changed partition;
- exact target release and manifest digest;
- public partition state immediately before and after the write;
- signer key id and approval;
- Hub deployment id, operation id, and audit record; and
- canary and delivery observations used for the decision.

Completion means all intended partitions name the target, two independent
public reads agree, a clean APM client accepts the target, retention roots are
installed, and the restricted and public evidence records are durable.

## Release classes and gates

| Gate | Edge | Candidate | Stable-eligible promotion | Emergency stable |
| --- | --- | --- | --- | --- |
| Clean protected source and contributor authorization | Required | Required | Required | Required |
| Hermetic build and closure/license audit | Required | Required | Required | Required |
| Repeat-build comparison | Targeted | Required | Reuse candidate evidence | Required |
| Threshold release metadata | Required | Required | Reuse candidate signatures | Required |
| External production Secure Boot signing | If image-bearing | If image-bearing | Reuse candidate signatures | If image-bearing |
| Full VM verified-boot/recovery suite | If image-bearing | Required if image-bearing | Reuse candidate evidence plus canary | Required if image-bearing |
| Hosted staging read-back | Required | Required | Reuse candidate plus freshness check | Required |
| Soak | None | Until superseded or selected | Seven days | May be shortened by incident commander |
| Progressive production partitions | No | No | Required | Required unless delay increases active exploitation risk |

No emergency class may waive signature verification, contribution
authorization, corresponding source, closure integrity, public read-back, or
boot/recovery checks for changed image code. It may shorten repeat observation
and may start with more stable partitions when the recorded incident analysis
shows that delay is the greater risk.

## Hub Worker application releases

Hub application deployment is related to, but not part of, a registry release.
The maintainer host follows the existing packaged-installer workflow:

1. Select an exact protected `master` commit and build one
   `pkg-aos-hub-cloudflare` installer closure.
2. Record its deployment id and store path and retain that closure.
3. Deploy it to the isolated staging Worker and validate public, authenticated,
   stateful, upload, image, range, indexing, and audit paths.
4. Promote the same installer closure and deployment id to production without
   rebuilding.
5. Re-run the relevant public and authenticated acceptance tests.

A Hub schema migration that is not backward compatible requires a signed
backup/restore and roll-forward plan before staging. Code rollback does not
pretend to reverse Durable Object, R2, KV, Queue, or registry state.

The content publisher pins an allowed Hub deployment-id range in its release
plan. A content release does not overlap a Hub deployment, topology cutover,
storage migration, or key rotation.

## Failure and recovery

Before a public pointer moves, failures are retried from the signed journal or
abandon the version. Already-uploaded immutable objects remain harmless and may
be reused only when their hashes match a later plan.

After a public pointer moves:

- freeze further publication and channel advancement;
- preserve the bundle, Hub audit entries, public responses, maintainer-host
  journal, and canary evidence;
- distinguish bad content, bad metadata, unavailable storage, compromised key,
  and bad Hub deployment;
- restore service availability without moving a consumer below its floor; and
- publish a higher fix-forward release for content or signed-metadata defects.

A storage or Hub database restore may restore service state only to a point
consistent with already-published immutable objects and public monotonic
pointers. It must not make a newer signed release or channel advancement
disappear. If that cannot be guaranteed, restore into isolation and reconcile
forward before accepting traffic.
