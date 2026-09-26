# 03 — Packaging, crates, units, and checks

This file states how Terrane enters the AOS tree: the crates and their
workspace placement, the Nix derivations, the systemd units and slices per
role, the module options, `aos-dev` targets, and the naming rule that maps
specification gates onto AOS checks.

Requirement IDs use the prefix `PKG`.

## Crates

Spec `37-crate-structure.md` defines five crates that carry no AOS
dependency. AOS adds one glue crate.

| Crate | Placement | Contents |
| --- | --- | --- |
| `terrane-core` | `crates/terrane-core` | `no_std` formats and algorithms (CRATE-1, CRATE-2) |
| `terrane` | `crates/terrane` | store, combinators, backends, repository, guard, GC; features `tokio`, `wasm` (CRATE-6 to CRATE-8) |
| `terrane-fs` | `crates/terrane-fs` | Linux surfaces; the only `unsafe` crate (CRATE-10 to CRATE-12) |
| `terrane-edge` | `crates/terrane-edge` | wasm32 bindings (CRATE-13, CRATE-14) |
| `terrane-cli` | `crates/terrane-cli` | the `terrane` binary and roles (CRATE-15 to CRATE-17) |
| `aos-terrane` | `crates/aos-terrane` | AOS glue: RFC-0021 trait impls, identity profile `aos-sandbox-v1`, domain map, Hub token issuer adapter, systemd wiring via `aos-systemd`, Crucible adapter (CRATE-18) |

- **[PKG-1]** The five specification crates MUST NOT depend on any `aos-*`
  or `crucible-*` crate (spec CRATE-18, CRATE-19). `aos-terrane` is the only
  crate that may depend on both. *Gate:* `checks.terrane.gates.crate-graph`.
- **[PKG-2]** The crates MUST be workspace members in `crates/Cargo.toml`
  with `[lints] workspace = true`, edition 2024, and the workspace's
  `clippy.toml` (no `HashMap`, no `Instant::now` outside the `Clock` trait).
  `terrane-fs` MUST set `#![deny(unsafe_op_in_unsafe_fn)]`; every other crate
  MUST set `#![forbid(unsafe_code)]` (spec CRATE-12, CRATE-30). *Gate:*
  `checks.terrane.gates.unsafe-audit`.
- **[PKG-3]** Adding the crates MUST update every affected
  `fetchCargoVendor` hash and the `aos` package's workspace test set, per the
  repository's Rust packaging rules (RFC-0015). *Gate:* `checks.eval`.
- **[PKG-4]** The binary MUST be named `terrane` (spec CRATE-15; decision
  [AD-1](06-decision-register.md)). AOS MUST NOT ship an `aos-terrane`
  binary; AOS-specific commands live under `aos terrane ...` in the `aos` CLI
  and call the SDK.

## Nix derivations

```nix
##! terrane — content-addressed, branchable filesystem store (RFC-0024)
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
  protobuf,
  fuse3,
  erofs-utils,
  zstd,
}: let
  version = "0.1.0";
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "terrane-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-...";
  };
in
  mkCargoPackage {
    pname = "terrane";
    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p terrane-cli --bin terrane";
    cargoEnv.PROTOC = "${protobuf}/bin/protoc";
    buildDeps = [protobuf];
    runtimeDeps = [fuse3 erofs-utils zstd];
    cargoNextest = true;
    cargoTestFlags = "-p terrane-core -p terrane -p terrane-fs -p terrane-cli";
    meta.description = "terrane — content-addressed, branchable filesystem store";
  }
```

- **[PKG-5]** `pkgs/tools/terrane.nix` MUST build only from AOS packages
  (`fuse3`, `erofs-utils`, `zstd`, `protobuf` from `pkgs/`), never from
  nixpkgs, per the repository's hermetic-build rule. Where `erofs-utils` or a
  ublk userspace library does not yet exist as an AOS package, the package
  MUST be added rather than the feature stubbed. *Gate:*
  `checks.terrane.package`.
- **[PKG-6]** `pkgs/tools/terrane-edge.nix` MUST build the wasm32 Worker
  artifact with the same toolchain path `aos-hub-worker` uses and MUST pass
  `checks.terrane.gates.core-no-std` and `checks.terrane.gates.feature-matrix`.
- **[PKG-7]** Every gate the specification names MUST exist as an AOS check
  `checks.terrane.gates.<gate-name>` where `<gate-name>` is the gate's name
  without the `gate:` prefix. A gate that needs a VM or KVM MUST set
  `requiredSystemFeatures = ["kvm"]` and live under `tests/terrane/`.
  Integration requirements in this directory use
  `checks.terrane.integration.<name>`. *Gate:* `checks.terrane.gates.registry-complete`
  (every gate in spec `36` has a check).

## systemd units and slices

The roles are one binary selected by `--role` (spec ARCH-10). Units mirror
the RFC-0021 slice layout so freezing a sandbox never freezes its filesystem
server (spec ARCH-11, FUSE-4).

| Unit | Role | Slice | Sandboxing |
| --- | --- | --- | --- |
| `terrane-serve.service` | `serve` | `aos-control.slice` | `DynamicUser=no`, dedicated user `terrane`, network allowed, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/terrane/state /var/lib/terrane/chunks` |
| `terrane-publish.service` | `publish` | `aos-view-services.slice` | `PrivateNetwork=yes`, sole writer of `/var/lib/terrane/sealed`, `CAP_FSETID` only if the filesystem requires it for fs-verity enablement |
| `terrane-fuse-worker@.service` | `fuse-worker` | `aos-view-services.slice` | `PrivateNetwork=yes`, `/dev/fuse` device access, memory, tasks, and descriptor limits per spec FUSE-5 |
| `terrane-gc.service` + `.timer` | `gc` | `aos-view-services.slice` | host-local collector (spec GC-25); the bucket collector runs where the authority runs |
| `terrane-job@.service` | `job` | `aos-view-services.slice` | tree jobs started through exposures (spec JOB-33) |
| `terrane-block@.service` | `realize` (block surface) | `aos-view-services.slice` | vhost-user-blk socket owner for Crucible and VMs |

- **[PKG-8]** Units MUST be declared through the `modules/` feature
  directory `modules/terrane/` with options, configuration, and checks kept
  together per the repository's Dendritic module rule. The privileged mount
  broker stays in `modules/sandbox/mount-broker.nix`. *Gate:*
  `checks.terrane.module-eval`.
- **[PKG-9]** No Terrane unit MUST run with `CAP_SYS_ADMIN`. Mount and
  passthrough registration are requested from `aos-mountd` over its
  descriptor protocol (spec ARCH-9). *Gate:*
  `checks.terrane.gates.no-privileged-mounts`.

## Module options sketch

```nix
options.aos.terrane = {
  enable = lib.mkEnableOption "the Terrane store and view service";

  store = lib.mkOption {
    # A store expression (spec 11-store-trait.md §Store expressions).
    type = lib.types.str;
    example = "routed[disk(/var/lib/terrane), remote(https://hub.example/api/terrane)]";
  };

  locality = lib.mkOption {
    type = lib.types.submodule { options = { region = ...; zone = ...; }; };
  };

  hostTier = {
    path = lib.mkOption { default = "/var/lib/terrane"; };
    sizeBytes = lib.mkOption { type = lib.types.int; };
    domains = lib.mkOption {
      # domain -> { filesystem = "/var/lib/terrane-private"; wipe = "zero"; }
      type = lib.types.attrsOf (lib.types.submodule { ... });
    };
  };

  exposures = lib.mkOption {
    # Rendered verbatim into the TOML `[[expose]]` list (spec 26 §Configuration).
    type = lib.types.listOf (lib.types.attrsOf lib.types.anything);
    default = [];
  };

  tokens = lib.mkOption {
    # Issuer public keys and the host token reference (spec AUTH-13, AUTH-35).
    type = lib.types.submodule { ... };
  };

  roles = {
    serve.enable = lib.mkOption { default = true; };
    publish.enable = lib.mkOption { default = true; };
    gc.enable = lib.mkOption { default = true; };
    edge.enable = lib.mkOption { default = false; };
  };
};
```

- **[PKG-10]** The module MUST render one `terrane.toml` from these options
  and MUST NOT accept free-form configuration text, so that spec CRATE-17's
  single configuration format is the only input the binary reads. *Gate:*
  `checks.terrane.module-eval`.

## `aos-dev` targets

```sh
bash ./aos-dev build package terrane
bash ./aos-dev build package terrane-edge
bash ./aos-dev list checks terrane.gates
bash ./aos-dev build check terrane.gates.tree-history-independence
bash ./aos-dev build check terrane.integration.viewd-role
bash ./aos-dev all checks
```

- **[PKG-11]** `aos-dev list checks terrane` MUST enumerate every gate and
  integration check, and `all checks` MUST include the non-KVM subset by
  default. *Gate:* `checks.terrane.gates.registry-complete`.

## Interactions

- Spec files `36`, `37`, `38`.
- [`01-sandbox-runtime.md`](01-sandbox-runtime.md) for slices.
- [`05-implementation-plan.md`](05-implementation-plan.md) Phase 1 and 3.
