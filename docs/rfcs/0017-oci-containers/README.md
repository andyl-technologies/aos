# RFC-0017: Scratch OCI containers from AOS package closures

- **Status:** Proposed
- **Date:** 2026-08-27
- **Audience:** maintainers of the Nix build graph, `aos`/`apm`/`apr`, AOS
  Hub, registry publication, release metadata, the Hub console, and runtime
  integration tests.
- **Relates to:** [RFC-0001](../0001-package-sandboxing/README.md),
  [RFC-0004](../0004-registry-hub/README.md),
  [RFC-0012](../0012-hub-surface-topology/README.md).
- **Architecture:** [`architecture.md`](architecture.md)
- **Plan:** [`implementation-plan.md`](implementation-plan.md)
- **Tests:** [`testing.md`](testing.md)
- **Phase-0 evidence:** [`phase0-evidence.md`](phase0-evidence.md)
- **Client compatibility:** [`../../users/aos-hub/oci-containers.md`](../../users/aos-hub/oci-containers.md)
- **GC operations:** [`../../plans/registry/oci-gc-runbook.md`](../../plans/registry/oci-gc-runbook.md)

## Summary

AOS will build OCI container images directly from realized AOS package
closures. Every image starts from an empty root, retains canonical
`/nix/store` paths, and is assembled with AOS-built tools. Building or running
the resulting image requires neither an upstream image, nixpkgs, a host Docker
builder, an AOS machine, nor a Nix daemon.

AOS Hub registries will contain OCI container repositories alongside their
packages, releases, binary-cache objects, and system disk images. Hub exposes
standard OCI Distribution endpoints for Docker-compatible clients and a
separate Connect control plane for AOS publication, signed-release provenance,
retention, garbage collection, and the Hub console.

The first and initially only registered container image is `aos`. Its package
baseline is derived from the production `systems.server` golden image's
`environment.systemPackages`, including the complete `pkgs.aos` wrapper
closure. It deliberately omits the kernel, initrd, boot loader, systemd boot
transaction, system toplevel, and host policy. Additional packages are
installed with user-scope APM or declared in a future Nix container definition,
following the same role that a minimal Debian base image serves for `apt`.

## Motivation

Today, running AOS software generally means installing Nix, running an AOS
machine or VM, or manually reconstructing a package closure. An OCI artifact
makes the same software directly runnable by ordinary container runtimes while
retaining AOS's hermetic source graph and signed publication model.

This feature has four independent consumers:

1. users who want to run AOS tools without changing their host;
2. CI jobs that need a reproducible AOS userspace;
3. application authors who want a scratch image containing only AOS packages;
4. Hub operators who need content-addressed distribution, provenance, quota,
   retention, and garbage collection.

## Goals

- Build OCI image layouts, archives, manifests, configs, and multi-platform
  indexes from AOS derivations only.
- Make layer bytes reproducible and intentionally reusable across images.
- Run dynamically linked AOS software from canonical `/nix/store` paths in a
  scratch filesystem.
- Make `aos`, user-scope `apm`, and `apr` useful without a Nix daemon.
- Publish and pull containers within an AOS Hub registry.
- Support standard Docker/OCI pull clients through `/v2/`.
- Preserve exact digest, signed release, source, license, and Nix closure
  provenance.
- Exercise the complete path through native Hub tests and the existing Hub Nix
  VM infrastructure.

## Non-goals

- Replacing AOS's native package sandboxing, systemd `RootDirectory=`, or
  signed `RootImage=` implementation.
- Treating an OCI image as a bootable AOS system image.
- Flattening Nix store outputs into an FHS filesystem.
- Using Docker, BuildKit, nixpkgs, a host tar implementation, or any upstream
  base image during the hermetic build.
- Making `apm --system`, boot activation, Secure Boot, TPM, VM, or system-image
  operations portable inside an ordinary container.
- Baking credentials, registry tokens, signing keys, SSH agents, or operator
  trust roots into an image.
- Registering application-specific container images in the first release.
- Cross-tenant physical deduplication.

## Locked decisions

### One initial image

The only repository-defined and Hub-registered image in the first release is
`aos`. The implementation may be generic, but evaluation checks reject an
accidental second registered definition until this RFC is deliberately
amended.

The `aos` image mirrors the production server golden image's interactive
package baseline by taking its package roots from:

```nix
systems.server.config.environment.systemPackages
```

The container definition adds no unrelated packages. `pkgs.aos` already joins
that list through the base APM module. Tests compare the evaluated store-path
sets rather than maintaining a second copied package list.

"Mirrors" means the userland package baseline and AOS release identity. It
does not mean the bootable system closure: containers have no kernel, initrd,
boot loader, systemd PID 1, host services, disk image, or host configuration.

### Scratch and canonical store paths

The builder has no `from` option. Package files remain under `/nix/store` so
ELF interpreters, RPATHs, absolute wrappers, and Nix references remain valid.
Conventional executable paths are symlinks into the immutable store.

### Container registry ownership

Container repositories belong to an AOS Hub registry. They inherit that
registry's tenant, authorization, placements, quota, signed releases, channels,
and audit boundary. OCI blob deduplication is scoped to one AOS registry.

Every registry receives one dedicated OCI authority. That authority selects
the owning AOS registry before `/v2/` routing begins; repository names below
`/v2/` are local to that registry. Hub-provided wildcard authorities and custom
domains follow the same one-authority-to-one-registry rule.

System images and containers share the registry boundary but not their storage
schema or delivery protocol. The existing `ImageService` remains exclusively
about bootable disk artifacts.

### Artifact and transport formats

The canonical build output is an OCI image layout. OCI archive and Docker
archive outputs are deterministic adapters. Hub stores and serves the original
blobs and exact manifest bytes rather than unpacking or reserializing them.

Hub implements the OCI Distribution API for generic clients. Connect RPC owns
repository administration, AOS-aware publication, provenance, tag promotion,
retention, and GC.

### Tags and signed releases

Digests are immutable. Manual tags are mutable compare-and-swap pointers and
are visibly unverified. Release tags are immutable once a signed AOS release
binds them. A channel tag advances only when all rollout partitions converge;
the AOS client otherwise resolves its partition directly to an immutable
digest.

### Runtime package management

The initial `aos` image includes the exact full `pkgs.aos` runtime closure. A
container init program creates a daemonless single-user Nix database, loads the
embedded registration stream, prepares writable APM/profile state, and then
executes the requested command.

The image initially runs as root because writing new paths into `/nix/store`
and its database is part of the promised APM behavior. Ordinary application
images should default to a non-root user once additional image definitions are
permitted. `/nix` is not declared as an OCI volume because an empty runtime
volume would hide the embedded store.

User-scope package changes survive restart of the same container. Reproducible
replacement deployments bake packages into a new image; cross-container
persistence of a mutated store is not a first-release guarantee.

Registration alone does not retain store paths across Nix garbage collection.
The image embeds its exact golden package-root list, and init atomically
reconciles symlink GC roots for that list on every start. This also repairs an
empty mounted Nix database before APM can run.

### Full CLI, not a misleading partial binary

The current `pkgs.aos` wrapper depends on command-specific runtime helpers.
Copying only the Rust executable would make behavior fail command by command.
The initial image therefore includes the full wrapper closure. Smaller CLI
profiles may be introduced only after command-specific outputs are implemented
and independently tested without removing features from `pkgs.aos`.

### Publication trust

Standard OCI clients validate registry TLS and content digests. AOS-aware
clients additionally verify signed AOS release metadata that binds the exact
OCI index digest, platform manifests, Nix output provenance, source, licenses,
SBOM, and referrer descriptors.

OCI publication scans the full closure. Packaging software in a layer does not
bypass corresponding-source requirements or the Crucible/QEMU licensing
boundary.

## Compatibility with RFC-0001

RFC-0001 correctly rejects an OCI runtime as the native AOS package sandboxing
substrate. This RFC does not change that decision. It defines an external
export and distribution format for running AOS software on non-AOS container
runtimes. AOS machines continue to install Nix closures with APM and expose
services through native systemd sandboxing.

## Completion criteria

The RFC is implemented only when all of the following are true:

- two equivalent builds produce byte-identical layer, config, manifest, index,
  layout, and archive bytes;
- the `aos` container package roots equal the production server golden image's
  `environment.systemPackages` roots;
- a standard container runtime loads or pulls the artifact and runs `aos`,
  `apm`, and `apr` without a Nix daemon;
- user-scope APM installs and executes a package from a local registry;
- a native local Hub accepts, catalogs, serves, and resolves the image;
- the Hub Nix VM checks publish, pull, load, and run the image;
- two manifests referencing one layer cause one physical registry write and
  correct quota accounting;
- private pull and push use repository-scoped bearer tokens;
- tag visibility is atomic after every required placement has the graph;
- signed release provenance binds the immutable OCI index digest;
- GC cannot collect anything reachable from a tag, signed release, referrer,
  lease, or active upload;
- all Nix, Rust, native Hub, VM, runtime, dialect, UI, and licensing gates pass.
