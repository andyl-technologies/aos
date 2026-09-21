# Certification examples

The repository keeps a small set of executable examples that exercise current
production interfaces. Most are build-time certification fixtures rather than
installed operator commands.

## Scenario authoring

[`crucible-e2e-determinism-scenario.rs`](../../../crates/crucible-api/examples/crucible-e2e-determinism-scenario.rs)
builds the representative three-VM scenario used by the end-to-end determinism
checks. It demonstrates canonical scenario construction, block and 9p objects,
signal bindings, node restart policy, and quantified properties. The
[quickstart](quickstart.md) uses its packaged generator.

## QEMU integration

| Example | Current contract | Repository check |
| --- | --- | --- |
| [`crucible-qemu-live-plugin-install.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-plugin-install.rs) | Installs the aggregate plugin protocol and validates sequence-valued white-box observations. | `checks.crucible.phase2.qemuLivePluginInstall` |
| [`crucible-qemu-live-block-realization.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-block-realization.rs) | Realizes the supported shared-memory block transport through the guarded launcher. | `checks.crucible.phase2.qemuLiveBlockRealization` |
| [`crucible-qemu-live-hot-fork-child.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-hot-fork-child.rs) | Exercises the contained native hot-fork child protocol. | Current hot-fork child checks |

Build the complete package and run its public self-test surface first:

```sh
nix build .#pkg-crucible
./result/bin/crucible selftest
```

Repository checks are hermetic and supply the matched QEMU, plugin, guest
assets, and process contract. Do not run certification examples with a
host-built QEMU or a separately sourced plugin.

When adapting an example, treat guest payloads, instruction ceilings, and
machine-readable `key=value` output as fixture details. Reuse the typed world,
signal, property, lifecycle, and protocol APIs documented by the public crates.
