# Runtime module sets

This extension lets an operator supplement the cloud-delivered `host.nix`
without replacing it. It keeps the two inputs distinct:

- `host.nix` remains the platform or signature-authenticated base module and
  remains the only input to initrd provisioning evaluation;
- `/var/lib/aos/config/modules.d` is a root-owned, stage-2 authoring worktree;
- an applied runtime module set is an immutable, recursively content-addressed
  snapshot of that worktree, retained by its configuration generation.

The stage-2 evaluator passes `host.nix` first and every discovered runtime
entrypoint after it as direct `operatorModules` entries. It must not synthesize
one wrapper whose `imports` point at the fragments: imported operator modules
have different precedence semantics from direct operator modules. Runtime
modules therefore have the same operator provenance and priority as the leaf
`host.nix`; ordinary module conflict rules reject incompatible definitions.

## Discovery

Discovery deliberately matches the repository's Dendritic module discovery:

- recursively include regular files whose names end in `.nix`;
- ignore files and directories whose names begin with `_`;
- reject symbolic links and every non-regular object;
- sort normalized relative paths bytewise before evaluation;
- limit the number of files, individual file size, and total bytes;
- keep helper files under `_` paths, where direct entrypoint discovery ignores
  them but relative imports from the same immutable snapshot remain possible.

The snapshot operation holds the root-owned worktree lock and copies from
already-open directory/file descriptors without following links. A path-based
validate-then-copy sequence is not sufficient because a concurrent rename can
replace a validated object before it is read. The resulting store path, NAR
hash, entrypoint list, and source tree hash are checked again before evaluation.

## Generation authority

The mutable worktree is never boot authority. `apm config apply` snapshots it,
evaluates a candidate against the currently active platform input and facts,
and commits a new configuration generation only if all of the following still
hold under the global switch lock:

1. the active configuration generation is the generation used as the
   candidate's base;
2. the running image generation and module ABI are unchanged;
3. every bootable A/B image capable of configuration reactivation declares
   support for the runtime-module-set generation and manifest feature;
4. the candidate manifest and every retained input validate;
5. materialization and activation complete through the existing atomic commit
   point.

A failed compare-and-swap is a stale-candidate error. The caller may explicitly
retry from a fresh snapshot; it must not let an older evaluation commit last.

At boot, rollback, cross-ABI re-evaluation, and attestation, the active or
selected generation supplies the exact retained runtime module set. Dirty,
partially edited, or absent worktree contents are ignored. The platform input,
runtime set, package configuration-module closure, facts, evaluator, and base
library are independently identified in the manifest and attestation record.
The per-generation `cfgsrc` root retains all of them, and garbage collection
may remove a runtime snapshot only after no retained generation refers to it.

## Compatibility gate

Adding runtime intent to a permissively deserialized generation record is not
forward compatible: an older fallback image could ignore the new field and
cross-ABI re-evaluate only `host.nix`, silently deleting the supplemental
intent. Runtime module activation therefore fails closed until every bootable
A/B configuration evaluator advertises the feature. The standalone recovery
environment does not re-evaluate or activate stage-2 configuration. Once a
generation requires the feature, normal boot and rollback refuse any evaluator
that does not understand it before re-evaluation or activation.

The manifest schema is versioned for the additional input rather than adding
an unrecognized field to `aos.config-manifest/v1`. Readers normalize v1 to an
empty runtime set, while v2 requires the complete identity. A v2 generation is
never made current while an incompatible A/B or recovery path remains
bootable.

## Operator interface

The configuration workflow is transactional:

```text
apm config status
apm config list
apm config add ./nginx.nix
apm config replace nginx.nix ./nginx.nix
apm config remove nginx.nix
apm config diff
apm config apply [--dry-run]
apm config discard
```

`add`, `replace`, and `remove` modify only the worktree through atomic renames.
`diff` and `apply --dry-run` compare the worktree candidate with the active
generation without committing. `apply` installs packages selected by the
composed modules through the existing resolve/evaluate fixpoint, so a module
can enable nginx, Envoy, or a Kubernetes role immediately after `apm` obtains
its package and authenticated configuration output.

## Package configuration interfaces

A package may publish its own `configModule`, and an ordinary package may act
as a meta-package whose module configures other installed packages. The
existing authorization rules remain the boundary:

- a package owns its exact package-name option root by default;
- a shared root has exactly one installed owner and an interface ABI;
- a meta-package may write only owner-declared contributable subpaths at the
  matching interface ABI;
- no package may enable another package; the operator runtime module selects
  packages and enables services;
- package modules receive only resolver-authenticated runtime outputs, never a
  builder-capable ambient package set.

Service artifacts should normally be projected from the package-private or
shared typed option root by the base/expose machinery. If a package must write
core artifact trees directly, authorization is exact-name scoped (one `/etc`
target, unit, user, or group), never ownership of the whole
`environment`, `systemd`, or `aos` root.

The three k3s role packages publish the same versioned `k3s` interface and are
mutually exclusive providers of that root. Its CNI and CSI integration
subtrees are contributable without allowing an integration package to enable
k3s. nginx owns the versioned `nginx` root and exposes contributable
virtual-host and upstream subtrees. Envoy owns the versioned `envoy` root and
exposes listener, cluster, endpoint, route, secret-reference, and runtime-layer
subtrees. Credentials are references to the credential channel and never
literal manifest values.

## Acceptance coverage

Pure checks cover deterministic discovery, ignored helpers, symlink, hard-link
and size rejection, direct-module precedence, package-prefix enforcement,
shared-root ABI matching, meta-package composition, manifest v1/v2 strict
validation, stale-candidate rejection, and retained-source rooting. Focused
package checks evaluate all three k3s roles and validate representative nginx
and Envoy configurations with their real binaries. The runtime lifecycle VM
installs and configures nginx, Envoy, and a k3s worker from two supplemental
fragments, then proves a failed candidate and a dirty worktree cannot replace
the pinned active generation across reboot.
