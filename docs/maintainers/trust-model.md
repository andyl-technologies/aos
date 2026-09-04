# Maintain the AOS trust model

Maintainers preserve a chain of authorization from reviewed source through a
booted system and its installed packages. No single signature provides every
property in that chain. Builds establish artifact identity, release roles
authorize specific artifacts, Secure Boot and dm-verity authenticate the
running image, and registry metadata authorizes package closures imported
later.

This guide defines the responsibilities attached to those boundaries. It does
not replace the command-by-command [canonical release
runbook](canonical-releases.md), the package review guidance in [Review package
security](package-security.md), or the wire-format reference under
[`docs/registry`](../registry/README.md).

Canonical production publication remains disabled until the launch gates in
[RFC-0017](../rfcs/0017-canonical-hub-publishing/README.md) are complete. The
checked-in Secure Boot keys are public test fixtures and provide no production
identity.

## Understand the composed chain

On a Secure Boot plus dm-verity system, the initial package trust anchor is
part of the authenticated operating-system root:

```text
reviewed source and fixed inputs
  -> hermetic Nix derivations and recorded NAR identities
  -> externally finalized image and release artifacts
  -> enrolled UEFI db verifies systemd-boot and the UKI
  -> the UKI authenticates its kernel, initrd, command line, and root hash
  -> dm-verity authenticates the immutable EROFS root
  -> the root supplies /etc/apm registry and configuration trust anchors
  -> signed registry history and TUF metadata authorize a release
  -> the signed store realization graph authorizes every selected NAR
  -> APM imports the verified closure into /nix/store
  -> activation measures exposed package identities and permissions into PCR 15
```

Secure Boot does not directly verify the root filesystem or an arbitrary Nix
store object. It authenticates the UKI. The UKI carries the root identity used
by dm-verity, and the authenticated root carries the first registry keys. That
embedding connects the boot and package trust chains without collapsing their
authorities.

The connection has two important limits:

- an image without dm-verity does not cryptographically bind its root
  filesystem to the signed UKI; and
- PCR 15 records explicitly activated exposed packages and configuration
  generations, not every object present in `/nix/store`.

The signed store graph remains the admission authority for downloaded closure
members. A signed dm-verity `RootImage=` adds block-level integrity while an
exposed workload runs. A non-verity store path is read-only to the confined
workload but is not protected from a host-root compromise after admission.

## Keep trust roles separate

Production policy assigns each authority one purpose. Protocol compatibility
does not authorize key reuse.

| Role | Authorizes | Must not authorize |
| --- | --- | --- |
| Firmware PK and KEK | Changes to the firmware Secure Boot key database | Registry releases, packages, or caches |
| Secure Boot db | systemd-boot, normal and recovery UKIs, and authenticated firmware payloads | Registry history or NAR substitution |
| Kernel-module signer | Loadable kernel modules for one compatible kernel policy | UKIs or package metadata |
| PCR-policy signer | Approved UKI measurements that may unlock sealed state | Firmware execution or registry history |
| Registry release signer | Registry commits, releases, key rosters, and store graphs | Bootable binaries, channel movement, or TUF root rotation |
| Registry channel signers | Partitions for one named channel, pointing only to releases allowed for that channel class | Release content or another channel |
| Nix-cache signer | Exact narinfo fingerprints | Registry names, releases, or channels |
| TUF roles | Root evolution, delegated release metadata, snapshots, and timestamp freshness according to role | Secure Boot or cache signatures |
| Provenance signer | Statements binding source, build, and artifact identity | Release selection or boot authorization |
| Release-evidence and qualification roles | Completion and qualification of a closed release | Artifact construction or Hub administration |
| Hub deployment and upload credentials | Writes to one deployment or registry surface | Artifact or package authenticity |

Registry and Nix narinfo signatures both use Ed25519-compatible formats, but
the canonical policy uses different keys. A verifier must never count one key
twice toward a threshold or treat a signature from one role as authorization
for another.

The current preview TUF implementation assigns its four top-level roles to the
active registry keys and signs them in one process. That is an implemented test
and development path, not the production role model in the table. A production
image must instead carry a threshold-authenticated TUF root in addition to the
registry continuity anchor, and the launch gate must prove role- and path-aware
verification. See [RFC-0017's security and key
architecture](../rfcs/0017-canonical-hub-publishing/03-security-and-keys.md).

Private production keys must not enter:

- the repository or a source archive;
- a derivation, builder environment, build log, or Nix store path;
- the registry clone, generated publication tree, or AOS Hub;
- a shell environment or command-line argument; or
- a release evidence bundle.

Public keys, certificates, identifiers, and verification policy are expected
release inputs. External or hardware-backed signers receive bounded,
domain-separated requests and return signatures that the coordinator verifies
against independently supplied public material.

## Preserve source and build identity

The package set is built hermetically from fixed source inputs with AOS-built
tools. Maintain that property when adding dependencies: no host tools, ambient
network results, unpinned source, or nixpkgs package may influence an output.

A successful build alone does not authorize publication. The canonical plan
freezes the source revision, package and image matrix, derivations, signer
roles, gates, deployment identities, and channels. The build step must then:

1. realize exactly the frozen derivations;
2. reject deriver or output-path drift;
3. record source and output NAR identities;
4. repeat builds with Nix `--check`; and
5. produce the SBOM and append-only evidence required by the plan.

Contributor authorization is a separate source-admission prerequisite. Follow
the [contributor licensing guide](contributor-licensing.md); never infer that a
reproducible build cures missing authorization.

## Maintain image trust

An ordinary Nix build must produce unsigned image assembly inputs. External
finalization binds an exact planned assembly to the Secure Boot, module, and
PCR-policy roles. The finalizer verifies signer responses, reconstructs every
download format to the same logical disk, and records the public artifact
identity before exposing the result.

When changing an image-baked trust anchor, review the change as an authority
transition rather than an ordinary configuration edit. The image contains:

- registry bootstrap keys under `/etc/apm/trusted-keys.d`;
- registry definitions and bootstrap caches under `/etc/apm/registries.d`;
- Secure Boot catalog certificates under `/etc/apm/trusted-sb-certs.d`; and
- signed-configuration keys under `/etc/apm/trusted-config-keys.d`.

The first three are authenticated by dm-verity when the root hash is bound by
the signed UKI. Signed `host.nix` may deliberately install a writable policy
overlay under `/var/lib/apm/config`; platform-trusted configuration may do the
same when the deployment chooses the platform metadata channel as authority.
Document and review that choice. The baked anchor establishes first contact,
not an immutable ban on later authorized policy changes.

Do not use the checked-in test keys for enrollment or storage sealing. A
production image requires deployment-owned firmware and signing roles,
enrollment, off-host recovery-key escrow, rotation, and recovery exercises.

## Maintain registry and store trust

A registry release authorizes more than a package name and store-path string.
Its authenticated tree includes the package catalog and the `store/`
realization graph. Every selected closure member must have a blessed NAR hash,
size, and dependency relationship. A missing, revoked, or inconsistent graph
member fails closed.

The Hub, object store, CDN, and binary cache transport bytes. They are not
allowed to choose trusted bytes. APM validates the decompressed NAR against the
signed realization graph before import. Signed narinfo additionally supports
the stock Nix substitution protocol; it is a separate cache-role authorization
and not a replacement for the registry release.

Maintain these invariants when publishing:

- finalize against a clean isolated clone at the exact planned base;
- include the complete closure rather than only package roots;
- verify catalog, store-graph, policy, documentation, source, and provenance
  bindings before creating the release commit and tag;
- generate the cache from that finalized registry, not a mutable authoring
  clone;
- publish immutable objects before channel or timestamp pointers;
- verify uploaded bytes through the public, unauthenticated read path; and
- advance consumers only through signed, monotonic, fix-forward state.

The first registry key must reach consumers outside the registry it secures.
An image-baked anchor is the normal path. A verified `keys.toml` roster may add
or retire keys after bootstrap, but a sole compromised key cannot safely
self-revoke in band.

## Maintain runtime attestation bindings

Measured boot and package admission answer different questions:

- PCR 7 records Secure Boot policy state;
- PCR 11 records UKI measurements and signed boot phases;
- PCR 12 records external boot inputs; and
- PCR 15 records activated exposed-package tuples and configuration
  generations.

The package event binds its name, version, root digest, and permission-manifest
digest. The configuration event binds the evaluated manifest and authenticated
inputs to the running image. A remote verifier must replay the event log and
check each tuple against the signed registry and image catalog; a PCR value
without its event log and authorization policy is not meaningful evidence.

Do not claim that PCR 15 measures inactive downloads, user-profile packages,
implicit dependencies as separate identities, or arbitrary store contents.
Those bytes are admitted through the signed realization graph.

## Review trust-changing changes

Treat a change as trust-changing when it modifies a key, trust directory,
signature format, signed schema, store graph, cache fingerprint, image catalog,
PCR input, release threshold, channel rule, or accepted configuration source.

Before merge, establish:

1. the authority being changed and the exact artifacts it may authorize;
2. the old-to-new compatibility and rollback behavior;
3. how existing installations learn the change without circular trust;
4. which compromised roles the separation still contains;
5. that no private material reaches evaluation or the store;
6. that parsers and verifiers fail closed on missing, duplicate, unknown, or
   malformed fields;
7. that negative tests exercise tampering, unknown keys, rollback, role
   confusion, and incomplete closures; and
8. that operator and incident documentation changes in the same patch.

Boundary changes should use the narrowest relevant evaluation, VM, fleet, and
release-pipeline gates. The canonical release plan remains the authority for
the exact gate matrix; passing a convenient local subset does not waive it.

## Respond according to the compromised role

Containment depends on preserving role separation:

| Compromise | Immediate consequence | Required response |
| --- | --- | --- |
| Registry key | Attacker may authorize catalog and store-graph changes | Stop publication, preserve evidence, retire with a surviving trusted key or distribute a new anchor out of band |
| Cache key | Attacker may mint narinfo signatures | Remove the cache, rotate its key, and continue requiring the independently signed registry graph |
| Hub or object-store credential | Attacker may alter or withhold served bytes | Revoke access, restore immutable objects, and verify public bytes; artifact signatures should prevent forgery |
| Secure Boot db key | Attacker may create bootable binaries | Stop image rollout, replace the db authority through the firmware process, rotate dependent artifacts, and recover affected machines |
| PCR-policy key | Attacker may authorize measurements for sealed-state unlock | Rotate policy authority and reseal through a verified recovery procedure |
| Sole registry bootstrap key | No safe in-band recovery exists | Ship a new anchor through a trusted image or independent operator channel |

Never repair a trust incident by deleting evidence, force-moving consumers
backward, or weakening signature requirements. Preserve immutable releases,
publish a higher corrected state, and re-establish the affected root through a
channel that does not depend on the compromised authority.

## Continue with the operational guides

- [Canonical release coordinator](canonical-releases.md) gives the production-
  shaped release commands and current launch boundary.
- [Build and customize release images](system-images.md) covers image policy and
  baked trust anchors.
- [Review package security](package-security.md) covers package implementation
  and confinement review.
- [Operate an AOS package registry](../users/registry/README.md) covers routine
  producer workflows.
- [Secure Boot and package trust](../users/aos/secure-boot.md) explains the
  resulting chain to system operators.
