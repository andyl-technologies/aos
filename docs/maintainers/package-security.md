# Review package security

AOS package security begins with a hermetic build and continues through the
package's typed ability declarations. Maintainers must review both boundaries:
a sandboxed build does not make the resulting program safe to run, and a
careful runtime declaration cannot repair an unauthenticated build.

The operator-visible runtime model is documented in [Understand native package
runtime policy](../users/aos/package-sandbox.md). Trust and publication duties
are documented in [Maintain the AOS trust model](trust-model.md).

## Preserve the build sandbox

Every package must build from fixed source with bootstrap tools and AOS
packages. Package expressions must not depend on host executables, host include
paths, upstream nixpkgs, undeclared environment state, or evaluation-time
network results.

Review source URLs, hashes, dependency locks, patches, generated sources, and
all build inputs together. Keep tools in `buildDeps`, linked or runtime inputs
in `runtimeDeps`, and propagated interfaces in `propagatedDeps`. Test the
installed behavior that matters instead of treating a successful derivation as
functional evidence.

## Review the native package contract

A package with runtime configuration publishes a `module` directory and explicit
`moduleDeps`. Its native input/result option modules, selected handlers, and
configured effects compose in the deployment fixed point. Reference docs and the
deferred transaction are derived from that configuration; package metadata must
not maintain a second unit, permission, credential, or dependency catalog.

See the [native runtime guide](../users/aos/runtime-abilities.md) for the current
API. Consumer migration is in progress, so the old `abilities` recipe field and
static provider/request maps are not the target for new code.

For each declaration, verify:

- the interface is provider neutral or clearly package specific;
- request schemas reject unknown and malformed fields;
- the package asks only for resources needed by its documented behavior;
- provider selection and aggregation remain deterministic;
- effects name their native owner and preserve rollback semantics;
- secrets use typed opaque references rather than Nix or store values; and
- qualification claims exercise the selected implementation.

Review the final module fixed point as the runtime authority. A package-local
projection is useful authoring feedback, but it cannot prove which provider or
resource the complete system selects.

## Review privileged effects explicitly

Treat writable host paths, host networking, devices, Linux capabilities,
kernel settings, firewall changes, static identities, and boot resources as
security-sensitive requests. Record why the workload needs each one, how the
native provider limits it, the test demonstrating the need, and the condition
for removing it.

Keep policy in the adapter that owns the resource. Do not weaken a global
preset to accommodate one package, and do not reproduce adapter policy inside
the package contract.

## Validate the change

Run the package build, its focused checks, the ability/package-contract checks,
and the system evaluation that selects it. Changes to live activation,
attestation, registry admission, or image policy also require the corresponding
VM or fleet gate.

Useful baseline commands are:

```sh
bash ./aos-dev build check effects --no-out-link
bash ./aos-dev build package PACKAGE --no-out-link
```

The relevant RFCs retain historical design context. Current package and module
code remains the authority for shipped behavior.
