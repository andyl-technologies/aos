# Certification examples

The repository contains executable examples that double as production
certification fixtures. They are the best implementation-backed starting
points for custom Rust integrations, but most are not installed as operator
commands and most gate names are not accepted by `crucible selftest`.

## End-to-end scenario examples

| Example | What it proves | Repository check |
|---|---|---|
| [`crucible-nginx-curl-http-200.rs`](../../../crates/crucible-api/examples/crucible-nginx-curl-http-200.rs) | Builds a workload guest, generates canonical scenario TOML, runs two live VMs, and grades a guest-originated HTTP result. | `checks.crucible.phase7.nginxCurlHttp200` |
| [`crucible-qemu-live-world-network.rs`](../../../crates/crucible-api/examples/crucible-qemu-live-world-network.rs) | Two live guests, deterministic lossy route, guest receipt, search choice, exact checkpoint, and fresh-process replay. | Included by `checks.crucible.phase2.qemuLiveNetworkIo` |
| [`crucible-qemu-signal-shared-cause.rs`](../../../crates/crucible-api/examples/crucible-qemu-signal-shared-cause.rs) | One event drives network forwarder power loss, storage cache loss, and node crash/restart with exact evidence and replay. | `checks.crucible.phase7.signalSharedCause` |

The Nginx/Curl program is explained in the [quickstart](quickstart.md). For new
fault authoring, begin with the shared-cause example: it shows the complete
topology, signal, binding, target, effect, artifact-store, lifecycle, evidence,
checkpoint, and replay path in one place.

## QEMU protocol and adapter examples

| Area | Examples | Representative check |
|---|---|---|
| Genesis, quantum stepping, preemption | `crucible-qemu-live-genesis`, `-live-node-step`, `-live-plugin-quantum`, `-live-plugin-preemption` | `checks.crucible.phase2.qemuLiveGenesisExecutor` and related phase-2 checks |
| Fingerprints and exact snapshots | `crucible-qemu-fingerprint`, `-live-plugin-fingerprint`, `-live-exact-snapshot` | `checks.crucible.phase2.qemuSingleVmFingerprint`, `qemuExactSnapshotRestore` |
| Network | `crucible-qemu-live-network-io` plus the world-network API example above | `checks.crucible.phase2.qemuLiveNetworkIo` |
| Block storage | `crucible-qemu-live-block-realization`, `-live-block-io`, `-live-block-node` | `checks.crucible.phase2.qemuLiveBlockIo` |
| 9p | `crucible-qemu-live-ninep-io` | `checks.crucible.phase2.qemuLive9pIo` |
| Node lifecycle | `crucible-qemu-live-node-lifecycle-fault` | `checks.crucible.phase2.qemuLiveNodeLifecycleFault` |
| CPU, memory, interrupt, clock, accelerator | `crucible-qemu-live-fault-hardware` and its matrix modules | `checks.crucible.phase2.qemuLiveFaultHardware` |
| Coverage and terminal boundaries | `crucible-qemu-live-coverage`, `-live-terminal-horizon`, `-live-terminal-targets` | Related phase-2 checks |

All source files are under
[`crates/crucible-qemu/examples`](../../../crates/crucible-qemu/examples) and
[`crates/crucible-api/examples`](../../../crates/crucible-api/examples).

## Running the supported checks

Build the complete package and run its public live subset first:

```sh
nix build .#pkg-crucible
./result/bin/crucible selftest
```

Maintainers can build a named repository check directly, for example:

```sh
nix-build -A checks.crucible.phase7.signalSharedCause
```

Repository checks are hermetic and supply the matching QEMU, plugin, kernel,
root image, initrd, and run directory. The check path named in the table is the
`nix-build -A` attribute; Crucible's nested repository checks are not all
flattened into flake `checks` outputs.

Do not invoke the examples with host-built QEMU or replace their AOS package
dependencies with host tools. Their results certify the versioned process and
shared-memory boundary only when the matched closure is used.

## Reading an example safely

Separate fixture details from reusable contracts:

- guest payload constants and instruction budgets are fixture-specific;
- `World`, `WorldFaultTopology`, signal, binding, and property construction are
  reusable authoring patterns;
- `ProductionVmLifecycleConfig` demonstrates the direct Rust lifecycle path,
  not an additional CLI configuration file;
- machine-readable `key=value` output is a gate contract, not the canonical
  event-log format; and
- helper modules under an example directory are part of that certification
  executable, not a stable library API.

For accepted CLI syntax use the [command reference](reference.md). For public
Rust contracts use the crate rustdoc and the types re-exported by `crucible`
and `crucible-api`.
