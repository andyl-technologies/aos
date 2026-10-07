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
| [`crucible-qemu-rom-clamp-stress.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-rom-clamp-stress.rs) | Drives 20,000 increasing 1,000 ps ceilings through the production node and its one-second completed-quantum acknowledgement guard. | `checks.crucible.phase2.qemuRomClampStress` |
| [`crucible-qemu-production-plugin-flight.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-production-plugin-flight.rs) | Observes original time ownership and an authenticated idle hold before the original timer grant. | `checks.crucible.phase7.qemuTimeOwnershipLive` |

Build the complete package and run its public self-test surface first:

```sh
aos-dev build package crucible
./result/bin/crucible selftest
```

Repository checks are hermetic and supply the matched QEMU, plugin, guest
assets, and process contract. Do not run certification examples with a
host-built QEMU or a separately sourced plugin.
Run `aos-dev` from the repository root in `nix develop` or its direnv environment.

The focused control and time checks can be selected directly:

```sh
aos-dev build check crucible.phase2.qemuRomClampStress --no-out-link
aos-dev build check crucible.phase7.qemuTimeOwnershipLive --no-out-link
```

The busy-ROM check uses fresh production launch admission, exact logical/raw
calibration, and owned process/storage cleanup. A retained run at
`e88c10ff8f` completed all 20,000 clamps: logical time advanced from 1,000,000 to
21,000,000 ps and raw instructions from 20,000 to 420,000. Its guest has no
network or Linux workload. This result does not qualify replay promotion,
network fault settlement, idle timer waits, or hot-fork children.

The live ownership check uses the real production plugin and QEMU's public
translated-block entry count, accounting for its precharged instruction debit.
It requires an original native wait spanning a 200 ms host hold with unchanged
logical/raw coordinates, followed by the authorized timer grant. A parser test
or a gate name alone does not qualify physical ownership; retain the result for
the exact tested revision. This check covers fresh processes, not fork-child
inheritance or the complete clock model.

When adapting an example, treat guest payloads, instruction ceilings, and
machine-readable `key=value` output as fixture details. Reuse the typed world,
signal, property, lifecycle, and protocol APIs documented by the public crates.

## Bounded diagnostic settings

These settings supply advisory observations for matching repository runs. They
are default-off and do not change guest coordinates, admission, control
outcomes, or timeouts. They are separate from the packaged `selftest` command
surface.

| Setting | Accepted value | Observation |
| --- | --- | --- |
| `CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS` | Integer from 1 through 256 | Enables bounded aggregate replay timing and fixed callback/settlement retention without the routine callback or native trace streams. |
| `CRUCIBLE_TIME_OWNERSHIP_WITNESS` | Exactly `1` | Enables bounded original time-owner, first-block, and admitted idle-wait observations for the ownership gate. |

The guarded child launch forwards only validated values through its cleared
environment. Invalid values are not forwarded. The aggregate setting does not
enable `CRUCIBLE_CONTROL_CALLBACK_WITNESS=1`; that legacy stream remains a
separate opt-in.

Replay timing has a fixed sixteen-row executor limit. Worker CPU excludes QEMU,
and session wall time includes caller gaps and teardown outside individual
phase totals. The event setting is not a global row budget across processes or
diagnostic producers.

With the aggregate setting alone, fixed callback and bridge-settlement records
are reported by the joined teardown owner only for an outstanding request or a
control fault. Rows are at
most 512 bytes and retain original node identity and observed request context.
They distinguish admission from settlement but cannot prove native eventfd
reader delivery. Contention, inherited identity, or missing observations may
produce an explicit unavailable record. Diagnostic sink failures do not replace
the original execution result.
