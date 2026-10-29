# OCI containers

AOS builds OCI container images directly from realized AOS package closures and
distributes them through AOS Hub registries. Images start from an empty root,
keep canonical `/nix/store` paths, and are assembled with AOS-built tools only:
no base image, Docker builder, nixpkgs, or host tar takes part. Running an image
needs neither a Nix daemon nor an AOS machine.

OCI images are an export and distribution format for ordinary container
runtimes. They do not replace native AOS package sandboxing, and an image is
not a bootable system: it has no kernel, initrd, boot loader, systemd PID 1, or
host configuration.

- [Image build](image-build.md) covers container definitions, closure layers,
  the layer archive ABI, metadata, and the runtime initialization contract.
- [Distribution and publication](distribution.md) covers the shared OCI
  contract crate, Hub's Distribution data plane, signed publication, and
  garbage collection.

User-facing behavior is in [Packages in AOS containers](../../users/aos/containers.md)
and [OCI container registry compatibility](../../users/aos-hub/oci-containers.md).
The signed release procedure that carries a container is part of the
[canonical release runbook](../../maintainers/canonical-releases.md).

## Pipeline

```text
system evaluation (aos.containers definitions)
        |
        +-- realized reference graph --> deterministic closure layers
        +-- PATH facade layer
        +-- root metadata layer
        +-- OCI config and platform manifest
        +-- multi-platform OCI index
                       |
               OCI image layout  (+ OCI archive, Docker archive)
                       |
          aos container push / publish
                       |
      +----------------+-----------------+
      |                                  |
Hub OCI Distribution API            Hub control plane
/v2/..., standard clients           Connect RPC and console:
                                    verified publication, retention, GC
```

The build and distribution planes share descriptor and digest validation
through `aos-oci-types`, but neither depends on the other. An OCI layout is
useful without Hub, and Hub accepts conforming OCI clients without running Nix.

## Code map

| Path | Role |
|---|---|
| `modules/image/container.nix` | Target-neutral selection of the container backend and the system-derived default definition |
| `pkgs/containers/_aos-oci-backend/` | The OCI backend: definition schema, the `aos` definition, image assembly, init script, evidence, and publication inputs |
| `pkgs/containers/_aos-oci-backend/oci/` | Byte-level builders: closure layers, metadata layer, image layout, multi-platform index, Docker archive |
| `crates/artifacts/aos-oci-types` | I/O-free OCI wire contracts shared by the CLI, native Hub, Worker, and browser console |
| `crates/artifacts/aos-oci` | Verified OCI layout, archive, and Distribution client operations |
| `crates/cli/aos-cli/src/commands/container.rs` | `aos container` build, inspect, pull, push, signing, and publish commands |
| `crates/hub/aos-hub-service/src/oci*.rs` | Hub Distribution routing, tokens, uploads, inventory, and GC controllers |
| `crates/hub/aos-hub-db/src/db/oci*` | OCI catalog, quota, retention, and GC persistence |
| `crates/packages/aos-package-manager/src/container_*.rs` | Container runtime detection, readiness admission, and startup for APM |

## Tests

`nix-build -A checks.container.all` aggregates the non-VM container checks:

| Check | Covers |
|---|---|
| `phase0` | The frozen layer byte vector, baked-root availability, daemonless store initialization, and root retention across Nix GC |
| `eval` | System and container evaluation contracts |
| `oci-builders` | Reference-graph deltas, layer reuse across derivation names, typed metadata, platform manifests, and a multi-platform layout |
| `evidence`, `evidence-platforms` | The evidence graph, its closure-layer bindings, and the signing seam |
| `runtime` | The production init transaction against an isolated local store, the facade, and absence of the kernel, initrd, and system toplevel |
| `shell` | Shared interactive shell defaults |
| `aos-runtime-closure` | The image runtime closure audit |
| `production-reproducibility` | Independent equivalent-input builds produce identical bytes |

The `aos-oci-types` golden tests freeze the wire formats, and the Hub crates
carry native Distribution, upload, recovery, and GC tests.
