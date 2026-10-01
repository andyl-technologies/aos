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
- registry Git commit, release tag, package catalog, documentation objects,
  and store realization graph;
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
- staging publication receipt and public read-back results;
- production publication receipts, rollout rings, channel observations,
  approvals, and any profile override with its incident reference; and
- the release-tool version and surface identities used for every transition.

It also carries the package eligibility matrix derived by applying the release
policy's selected four targets to package-owned `platformSupport` declarations,
plus both Linux architecture image matrices defined by
[`06-platform-matrix.md`](06-platform-matrix.md). Every planned cell is an
artifact, an explicit policy-backed `not-applicable`, or a `blocked` result.
A plan with a `production/stable` destination, whose `soak` profile requires a
complete matrix, contains no blocked cell.

TUF root, targets, delegated-targets, snapshot, and timestamp files are
repository metadata on the registry surface, not targets inside this bundle.
The delegated release entry authorizes the signed manifest envelope; that
manifest inventories every bundle payload. This direction is intentional: if
the manifest inventoried TUF bytes that themselves named the manifest or whole
bundle digest, construction would require a cryptographic hash fixed point.
Exact-byte publication receipts separately bind the resulting bundle digest.

The public portion is signed by the provenance/evidence key and published with
the release. Secrets, personal data, provider account ids, internal host
addresses, and raw logs remain in the restricted operator record; the public
manifest carries their digests and pass/fail claims.

## States

One release id advances monotonically through three global states and then
through one state per planned destination. The hash-chained journal
(`aos.release.journal-entry/v1`) records each transition:

```text
planned -> built -> finalized -+-> published(staging/c)    -> rolling -> complete
                               +-> published(production/c) -> rolling -> complete

any non-terminal state -> failed
```

- `planned`, `built`, and `finalized` are global and linear.
- `published(d)` requires `finalized` and a published, rolling, or complete
  entry for every surface role that destination `d` lists in `after`.
  Production destinations list staging; staging destinations list nothing.
- `rolling(d)` records each ring advance; `complete(d)` closes the
  destination's rollout.
- Destinations interleave. `production/candidate` and `production/stable` of a
  final version advance independently once staging is published.
- The release succeeds when every planned destination is `complete`.

There is no `qualified` state. The signed staging qualification of a
production destination is evidence attached to that destination's
`published` entry; rollout and completion qualifications attach to the entries
they authorize.

`failed` is terminal for the release bytes. A failed version is never reused.
An interrupted transition may resume only from a verified journal whose inputs
and already-written immutable objects match the bundle manifest.

### `planned`

The release plan freezes:

- release version and the class derived from it (`edge`, `candidate`, or
  `stable`);
- exact source commit;
- the staging and production surfaces: kind, origin, read-back origin, and
  identity;
- every destination with its profile digest, gates, soak, and rollout rings;
- the change scope against the predecessor release;
- any accepted profile override, by digest;
- package, image, documentation, source, and license artifact matrix;
- build and signing tool closures;
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
- complete package/NAR/documentation checks for `x86_64-linux`,
  `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`;
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
digests, exact target platform, PE machine type where applicable, key role,
requested signature purpose, and operator approval before it uses a key.

For an image-bearing release, finalization performs these steps independently
for each Linux architecture:

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

### `published` to a staging destination

The maintainer host obtains a short-lived, staging-only upload credential. It
uploads immutable objects first and mutable registry discovery data last to the
isolated staging surface. A Hub surface verifies the bundle signature, expected
staging deployment id, registry identity, object hashes, sizes, completeness,
and compare-and-swap base before it admits the publication. On a static
surface the maintainer host performs the same checks, confirms the
`.aos-surface` identity before and after upload, and signs the receipt with the
surface-receipt role.

Read-back is from the staging surface's public route, such as
`aos.staging.andyl.org`, not from the local authoring clone or provider storage
endpoint. Every object is fetched by its public route and compared with the
manifest. Range requests are checked for image artifacts. The staging
destination's `build` profile has no further gate: its channel moves across all
partitions once read-back succeeds, so executors consume the release through
the same channel protocol clients use.

Staging registry metadata may refer to the canonical production cache URL. A
staging APM test uses an explicit staging cache override until the immutable
objects are present in production. Environment-specific cache URLs must not be
baked into the release commit merely to make staging work.

### Staging qualification

Qualification boots and exercises the exact finalized bytes read back from the
staging surface. It must not substitute a local image or regenerate a metadata
file. It is evidence for a production destination, collected under that
destination's profile, and it is admitted when the destination is published;
it is not a journal state.

An image-bearing release qualified for `production/candidate` or
`production/stable` passes:

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
- clean surface logs, storage checks, ranged downloads, cache headers, and
  audit entries.

Qualification runs both Linux image architectures and the native Darwin
package gates required by [`06-platform-matrix.md`](06-platform-matrix.md).
Cross-compilation and static inspection alone cannot qualify a Darwin cell for
stable.

A change-scoped `smoke` qualification for `production/edge` exercises only
what differs from the predecessor. A package-only edge release installs and
activates each changed package cell in its supported system context, verifies
package-root integrity and documentation, proves from the recorded change scope
that no image-affecting input changed, and has no unreviewed finding that
violates the channel policy. An uncertain change scope selects every target. A Hub Worker release follows the separate
application path below.

### `published` to a production destination

Production publication copies the bundle's existing immutable objects to the
production surface and imports its existing signed registry objects. It never
invokes Nix, `ukify`, an image converter, a content signing key, or a metadata
generator.

The production surface requires:

- a short-lived credential scoped to the production surface of this registry;
- the exact bundle id and the staging publication receipt;
- the planned production surface identity, checked before and after upload;
- the destination's signed staging qualification, covering exactly its planned
  gates under the recomputed change scope, with the profile's reviews;
- fitness attestations required by the profile, within their maximum age and
  bound to the live surface, schema, signer roster, tooling, and alert
  configuration;
- object-by-object digest and completeness verification;
- a compare-and-swap base matching the recorded production generation; and
- no active publication or topology migration.

Production immutable objects are uploaded first. The registry snapshot becomes
discoverable only after every referenced cache, image, documentation, source,
and recovery object is readable and verified. A clean consumer with only the
image-baked trust root must verify the release from the public production
route before any supported channel changes. When a final version is published
to `production/stable` after `production/candidate`, the surface already holds
its publication; the stable destination verifies it by full read-back and moves
only its own channel.

### `rolling` and `complete`

Each production destination advances the rings of its profile. `edge` and
`candidate` advance all partitions in one ring after production read-back;
`candidate` first requires a fresh reviewed rollout-health approval. An
image-bearing candidate therefore imports its qualified image objects before
the candidate pointer moves. A stable release reuses those production objects,
advances the four recorded canary partitions, observes the ring, and proceeds
through the cumulative `4 -> 32 -> 128 -> 256` plan, with a fresh reviewed
health approval before every ring.

Each advancement is an independent, signed, compare-and-swap operation. The
operator records:

- expected old release per changed partition;
- exact target release and manifest digest;
- public partition state immediately before and after the write;
- signer key id and approval;
- surface identity, operation id, and audit record; and
- canary and delivery observations used for the decision.

Completion of a destination means all intended partitions name the target, two
independent public reads agree, a clean APM client accepts the target,
retention roots are installed, the release-evidence completion approvals are
signed, and the restricted and public evidence records are durable. A `soak`
destination additionally requires the signed complete-phase observation report
covering its full soak.

## Profiles and gates

Each destination selects one profile. The shipped profiles are:

| Gate | `build` (staging destinations) | `smoke` (`production/edge`) | `functional` (`production/candidate`) | `soak` (`production/stable`) |
| --- | --- | --- | --- | --- |
| Clean protected source and contributor authorization | Required | Required | Required | Required |
| Hermetic build, repeat-build comparison, closure/license audit | Required | Required | Required | Required |
| Threshold release metadata and external image signing | Required | Required | Required | Required |
| Hosted staging read-back | Required | Required | Required | Required |
| Functional claims and package cells (A2) | No | Changed targets and cells only | Every target and cell | Every target and cell |
| Qualified claims (A3) | No | No | No | Required |
| Independent report review | No | No | One reviewer | One reviewer, including each ring |
| Registry transaction review | No | No | Required | Required |
| Complete package/image matrix | No | No | No | Required |
| Fitness attestations | No | No | Weekly automated (14 days); quarterly restore and authority recovery (90 days) | As `functional`, plus quarterly key rotation |
| Rollout health approval | No | No | Before the single ring | Before every ring |
| Soak | None | None | None | Seven days |
| Progressive production partitions | No | No | No | 4, 32, 128, 256 |
| Overridable by a signed profile override | Nothing | Nothing | Nothing | Soak (minimum one day) and rings (ending at 256) |

Build-side gates run once per release: a final version's candidate and stable
destinations share one build, one signature set, and one staging publication.

No release class relaxes obligations. An emergency is a `production/stable`
release planned with a threshold-signed profile override that references an
incident record. The override changes the plan digest, so it is fixed before
any build.
No override may waive signature verification, contribution authorization,
corresponding source, closure integrity, public read-back, review, fitness,
the complete matrix, or boot/recovery checks for changed image code. It may
shorten observation and may start with more stable partitions when the
recorded incident analysis shows that delay is the greater risk.

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

When a surface is a Hub, the content publisher pins its deployment identity in
the release plan. A content release does not overlap a Hub deployment,
topology cutover, storage migration, or key rotation.

## Failure and recovery

Before a public pointer moves, failures are retried from the authenticated
hash-chained journal and its signed transition evidence or abandon the version.
Already-uploaded immutable objects remain harmless and may be reused only when
their hashes match a later plan.

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
