# Review package security

AOS package security has two separate isolation boundaries. Nix builds isolate
how source becomes a store output. The optional package `expose` contract
controls how APM activates services from that output. Maintainers must preserve
both; a sandboxed build does not make the resulting program safe to run, and a
confined service cannot repair a non-hermetic or unauthorized build.

This guide is for maintainers adding or reviewing packages. The user-visible
runtime model is documented in [Understand the package
sandbox](../users/aos/package-sandbox.md), and trust and publication duties are
documented in [Maintain the AOS trust model](trust-model.md).

## Preserve the build sandbox

Every package must build from fixed source with bootstrap tools and AOS
packages. Package expressions must not depend on host executables, host include
paths, upstream nixpkgs, undeclared environment state, or evaluation-time
network results.

When reviewing a package:

- keep source URLs, versions, and hashes together in the package expression;
- declare build-only tools in `buildDeps` and linked or runtime requirements in
  `runtimeDeps`;
- use explicit store paths in generated commands;
- use the builder's POSIX shell and `$CONFIG_SHELL` where Bash is required;
- never introduce `/bin/sh`, `/bin/bash`, or `/usr/bin/env` outside the
  documented bootstrap and VM-root exceptions;
- preserve upstream features by packaging their dependencies instead of
  disabling them for convenience; and
- verify that tests exercise the built output rather than a host installation.

Nix sandbox enforcement is part of the release evidence, but it is not the
only hermeticity control. A build script that deliberately reads an undeclared
input or downloads mutable content is still defective even if it happened to
run in a permissive local daemon.

## Decide whether the package exposes services

A plain derivation may be installed into a profile or included in an image. It
does not receive an APM-managed runtime sandbox merely by existing in
`/nix/store`. Directly executing a profile binary also does not enter a package
sandbox.

Use `expose` when APM must own a service's activation contract:

```nix
expose = {
  units."acme-agent.service" = {
    description = "Acme agent";
    serviceConfig = {
      Type = "simple";
      ExecStart = "${agent}/bin/acme-agent";
      Restart = "on-failure";
    };
  };

  permissions = {
    network = "private";
    tcp-bind = [];
    capabilities = [];
    devices = [];
    host-paths = [];
    syscalls = "restricted";
  };
};
```

The renderer produces eval-free activation artifacts, normalized permissions,
the computed confinement class, and `aos-pkg-<name>.target`. Registry
publication signs the runtime contract along with the package metadata. A
maintainer must not hand-edit generated units or signed metadata to bypass the
renderer.

## Start from the empty permission manifest

An empty or least-privilege manifest is the baseline. For a confined workload,
the renderer supplies a package-private root, private temporary and device
views, a private user identity, an empty capability set, syscall filtering,
systemd hardening, and Landlock filesystem policy. Network policy is generated
from the declared mode and TCP grants, with eBPF enforcement where the confined
network model requires it.

Add one permission only when the service cannot function without it. Record the
reason in the package or change description when it is not evident from the
service protocol.

| Permission | Review question |
| --- | --- |
| `network` | Can the service remain isolated, or use private outbound networking rather than the host namespace? |
| `tcp-bind` and `tcp-connect` | Are the exact ports required, and do host firewall and listener policy agree? |
| `capabilities` | Can a narrower service design avoid the capability? Does it make the process root-equivalent? |
| `devices` | Is the exact device node required, and can access be read-only or brokered? |
| `host-paths` | Is the path minimal, and is read-only sufficient? Could a service directory replace it? |
| `cgroup-delegate` | Does the workload genuinely manage descendant cgroups? |
| `privileged-users` or static users | Why is the private identity model insufficient? |
| `kernel-modules` | Is the module allowed by host policy and signed for the running kernel? |
| `syscalls` | Can the restricted profile work? Why is a broader named profile necessary? |

Free-form syscall filters and undeclared side effects are not portable package
interfaces. Extend a named, reviewable policy surface instead of inserting an
escape hatch into one unit.

## Interpret the confinement class honestly

The confinement label is computed from normalized permissions; packages do not
choose it.

- `sandboxed` means the package retained the default boundary without declared
  holes.
- `sandboxed-with-holes (...)` lists permissions that weaken the default while
  retaining a meaningful boundary.
- `unconfined` means root-equivalent grants make the package target a packaging
  and lifecycle boundary rather than a security boundary.

`CAP_SYS_ADMIN`, privileged user handling, or writable system locations are
root-equivalent. High-privilege software such as k3s must display as
`unconfined`; do not special-case its label or describe its package wrapper as
a containment boundary.

Host networking is an explicit downgrade because per-package TCP enforcement
cannot isolate a process sharing the host namespace in the same way. Other
filesystem, credential, capability, syscall, and systemd restrictions can
still apply when the overall package is not root-equivalent.

## Keep host-side effects behind the package target

Some requested actions cannot safely occur inside the workload service. The
renderer implements them through narrowly generated host-side services owned
by `aos-pkg-<name>.target`, including approved kernel-module, sysctl, firewall,
network-namespace, MAC-policy, and eBPF-policy work.

Review these as privileged helpers, not as evidence that the workload itself
received the corresponding host capability. In particular, a package that
requests a kernel module must never receive `CAP_SYS_MODULE`. Host policy
allowlists and loads the named module through the generated helper.

The target is the lifecycle boundary. Starting it brings up the declared
helpers and workload units in the required order; stopping it must remove
reversible grants and services coherently. Units marked for manual start are
installed but do not join the target automatically.

## Review filesystem and runtime integrity

A confined non-verity service runs from a volatile overlay `RootDirectory=`
whose immutable lower layer is the authenticated package payload. Writable
state belongs in declared service directories or explicit host-path grants,
not in the store output.

A package may instead publish a signed dm-verity root image. The generated
service then uses `RootImage=`, its root hash and signature, and the required
device ordering. This provides block-level integrity while the workload runs.
It is not compatible with an `unconfined` permission set.

Do not overstate the non-verity case. Registry verification authenticates the
bytes at admission, and the read-only store protects ordinary mutation paths,
but only the signed dm-verity workload root supplies continuous block-level
verification of the executed payload.

## Preserve configuration and secret boundaries

Configuration must use the package's typed `configModule` and generated
artifacts. Modules receive only explicitly declared output mappings; they must
not import an ambient package set or evaluate arbitrary registry content.

Secrets use opaque references and systemd credentials. Never place secret
bytes in:

- a package expression or source tree;
- a Nix string, derivation input, output, or store-backed environment file;
- the signed expose manifest; or
- a command line visible through process inspection.

Declare which units consume a credential and whether it is required. A package
may describe a secret interface; the deployment supplies the value.

## Preserve package attestation meaning

For every explicitly activated machine-wide package with `expose` metadata,
APM extends PCR 15 with a tuple binding the package name, version, root digest,
and permission-manifest digest. Configuration activation also records its
authenticated module inputs and running image relationship.

The measurement does not cover:

- user-profile packages;
- downloaded but inactive roots;
- every dependency as an independent package event; or
- arbitrary objects already present in `/nix/store`.

Those bytes remain authenticated by the signed registry realization graph. Do
not change tuple construction, event ordering, CEL persistence, or quote
verification without treating it as a trust-model and compatibility change.

## Run the package security review

Before merging a new exposed package or a permission change:

1. Build the exact package from fixed inputs.
2. Inspect the payload and rendered expose manifest.
3. Confirm that the computed confinement label matches the effective grants.
4. Review every capability, device, host path, port, static identity, syscall
   profile, module, sysctl, and firewall side effect.
5. Confirm that declared service commands survive Landlock wrapping and use
   absolute store paths.
6. Check that configuration dependencies and credential consumers are
   explicit.
7. Test target start, stop, restart, failure, removal, and generation rollback.
8. Add negative coverage for any new permission or parser behavior.
9. Verify registry publication and re-consumption of the signed manifest when
   its schema changes.
10. Update operator documentation when a package gains a new privilege or
    changes its network or state contract.

Run the narrow checks relevant to the change. The common package-contract
gates include:

```sh
nix-build -A checks.package-expose --no-out-link
nix-build -A checks.package-expose-lifecycle --no-out-link
nix-build -A checks.eval --no-out-link
```

Also build the package's `pkg-<name>` output and run its package-specific tests.
Changes to live activation, attestation, registry admission, or image policy
require the corresponding VM or fleet gates; evaluation alone is not runtime
evidence.

## Keep the documentation boundaries clear

- [Package an application for AOS](../users/aos/package-authoring.md) is the
  end-to-end authoring tutorial.
- [Understand the package sandbox](../users/aos/package-sandbox.md) explains
  effective behavior to an operator.
- [Configure package registries](../users/aos/registries.md) explains package
  origin and admission trust.
- [Maintain the AOS trust model](trust-model.md) covers signing authorities,
  release trust, and compromise response.
- [RFC-0001](../rfcs/0001-package-sandboxing/README.md) retains the design
  history and detailed rationale.
