# Support boundaries

This page distinguishes Crucible features that are usable through the packaged
operator workflow from public model surfaces, repository certification
programs, and intentionally rejected future concepts. Read it before treating
a type or CLI flag as a production-support promise.

## Support vocabulary

| Status | Meaning |
|---|---|
| Packaged | Available through `nix build .#pkg-crucible` and the installed `crucible` CLI. |
| Public API | Available to Rust scenario generators or lifecycle integrations, but not necessarily exposed as a CLI command. |
| Certified | Exercised against patched QEMU by a repository Nix gate or executable example. The gate may not be selectable by `crucible selftest`. |
| Model only | Admitted and evaluated by the deterministic host model, but without a packaged guest-device or operator workflow. |
| Rejected | Representable as a physical concept in documentation or schemas, but deliberately rejected at admission because its production adapter is incomplete. |

“Supported” in the effect catalog means that the closed model, target
validation, adapter contract, evidence, checkpoint state, and replay behavior
exist. It does not mean every effect has a dedicated high-level CLI flag.
Faults are authored in a scenario and executed by the matching adapter.

## Execution and control planes

| Surface | Status | Boundary |
|---|---|---|
| Local patched-QEMU lifecycle | Packaged, primary | Linux host; validated QEMU/plugin pair; durable run-state directory. |
| `run`, `verify`, save/resume/fork, replay | Packaged | Operate on canonical scenarios, schedules, checkpoints, and artifacts. See the [command reference](reference.md#command-line-interface). |
| Bounded search, fuzzing, triage | Packaged | Search and campaign budgets must be explicit; only admitted choices are explored. |
| Interactive/debug workflow | Packaged with narrower paths | Some operations require a running daemon session, a retained checkpoint, a debug-capable guest, or an explicit non-canonical fork. |
| HTTP/2 daemon | Packaged, limited fidelity | The daemon exposes the documented lifecycle routes; it is not a distributed scheduler or a remote equivalent of every local CLI path. |
| Distributed campaigns and fleet storage | Public/certification surfaces | Repository APIs and gates exist, but there is no general packaged fleet operator workflow. |

The packaged CLI discovers only its matched patched QEMU and plugin. It does
not use arbitrary host QEMU builds, KVM, `tc`, `netem`, host namespaces, or
host-side traffic generation as substitutes for modeled execution.

## Host and guest architectures

- The host must be Linux. The repository flake evaluates on `x86_64-linux` and
  `aarch64-linux`.
- The packaged production command is currently wired to
  `qemu-system-x86_64`. Treat x86-64 as the documented operator path.
- The scenario and lifecycle APIs contain AArch64 capability and guest-asset
  types, and repository gates exercise architecture-specific contracts. Their
  presence does not make AArch64 a packaged operator guarantee.
- The local lifecycle accepts per-architecture assets through its Rust API,
  but the packaged CLI currently launches its nodes from one process-wide
  kernel/root-image configuration. Heterogeneous per-node images are not an
  operator-supported workflow.

## Fault domains

| Domain | Execution status | Target families |
|---|---|---|
| Network | Live production adapter | Interfaces, segments, media, forwarders, queues, paths, attachments, contacts, services, and profiles. |
| Block storage | Live production adapter | Device/range, controller/path, array, cache, persistence, media, data, result, and service targets. |
| 9p | Live production adapter | Result, data, visibility, and service behavior for declared 9p nodes. |
| VM lifecycle | Live production adapter | Crash, restart, reset, power-cycle, boot policy, hang, and state-retention behavior. |
| CPU, interrupt, memory, clock | Matched QEMU capability adapters | Exact declared registers, instructions, address spaces, interrupt routes, and clock sources only. |
| Accelerator | Matched deterministic QEMU fault device | Declared GPU/TPU/FPGA-class device capabilities; not arbitrary passthrough hardware. |
| Physical causes | Host model | Time, events, traces, motion, position, temperature, radiation, vibration, weather, and other typed signals may drive supported effects. |
| Sensor, battery, power, cooling devices | Rejected as executable targets | These may be modeled as causes, but no guest device adapter is admitted for them. |

The exhaustive executable effect, source, operator, target, phase, lifetime,
and operation vocabulary is in the
[canonical reference](reference.md#plans-signals-bindings-and-faults). The
[signal-driven fault guide](signal-driven-faults.md) explains how those pieces
compose.

Normalized trace import and evaluation are public APIs. Local search attaches
the selected DAG store and replay can carry authenticated signal objects, but
ordinary packaged `run` and `verify` do not currently attach `--store` as the
lifecycle signal-artifact store. See [Recorded signal inputs](recorded-signals.md)
before designing a trace-driven operator workflow.

## Determinism and recovery guarantees

The local production path records scheduler choices, fault samples, resolved
targets, adapter evidence, and fingerprints in guest coordinates. It supports:

- canonical event logs and independent reduction with `verify`;
- exact, durable whole-world checkpoints at admitted boundaries;
- save, resume, fork, and fresh-process replay;
- locked resolved-effect replay and recomputed signal replay where the selected
  API or artifact carries that material; and
- bounded counterfactual search over explicitly declared choices.

Those guarantees stop at the deterministic boundary. Wall-clock performance,
host scheduling, arbitrary external services, undeclared devices, and traffic
generated outside the guests are not replay inputs.

## Built-in self-test versus repository certification

`crucible selftest` intentionally exposes only the live gates listed in
[Running Crucible](running.md#self-test). Many more production behaviors are
certified by Nix checks and executable examples. A gate existing in the source
tree does not imply that its name is accepted by `selftest`.

Use the [certification examples](examples.md) to find the implementation-backed
example for a feature. Maintainers can run the named Nix check; operators
should normally build the complete package and use the packaged self-test
before running their own scenario.

## How to decide whether a workflow is supported

Check all four layers:

1. The effect or operation appears in the [reference](reference.md).
2. Its target exists in the world's immutable fault topology and validates
   against the selected effect and phase.
3. The selected backend advertises the required capability before boot.
4. A packaged path or named repository certification example covers the
   behavior you intend to depend on.

Admission and capability negotiation fail closed. Do not infer support from a
Rust enum alone, and do not bypass validation by editing generated content
hashes.
