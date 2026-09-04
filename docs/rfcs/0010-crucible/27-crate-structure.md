# 27 — Crate Structure (the L0–L4 workspace)

This file specifies the Cargo workspace: the crates, what each one owns and does
*not* own, the acyclic dependency graph, the crate-level safe/unsafe fence, the
feature flags, the determinism boundary, and how the per-layer gates of
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) map onto
crate test suites. It is the physical realization of the L0–L4 layering sketched
in [`03-architecture-overview.md`](03-architecture-overview.md) §4 and the
dependency rule `ARCH-3`. Engineering *standards* (the doc lint, the Rust
documentation bar, naming) live in
[`28-engineering-standards.md`](28-engineering-standards.md); this file owns the
*shape*. Requirements here carry the `CRATE` prefix
([`00-conventions.md`](00-conventions.md)).

The design principle is one principle restated at the package level: **the
determinism contract is enforced by the dependency graph, not by discipline.**
The pure engine cannot accidentally call wall-clock code or touch raw guest
memory because the crates that *can* do those things sit below it behind traits
and are not in its dependency set. A reviewer reads one crate-root attribute and
one `[dependencies]` table and knows the regime that applies to every line in
that crate.

> This RFC is design-only; the crate tree below is the *target*. Nothing here
> ships until the phased plan in
> [`32-implementation-plan.md`](32-implementation-plan.md) is worked through and
> each layer's determinism gate is green.

## 1. The crate map (L0–L4)

Crucible is **eighteen runtime crates** plus the test-only `crucible-harness`
package in the AOS Rust workspace, partitioned into five Crucible layers. The
`CRATE-*` "exactly" and "only" requirements in this file are scoped to the
Crucible package set, not to the pre-existing `aos-*` packages that share the
repository workspace. Lower Crucible layers never depend on higher Crucible
layers (`ARCH-3`). The engine crate and the CLI binary are *both* named
`crucible`: the L3 library crate is the package `crucible` (the engine), and the
L4 binary crate `crucible-cli` produces the binary named `crucible`. (The
umbrella/library is `crucible`; the shipped executable is `crucible` via
`[[bin]] name = "crucible"` in `crucible-cli`. See §7 for the `[bin]`/`[lib]`
split.)

```text
  L4  CONTROL PLANE
    crucible-session   actor owning one live RuntimeState; control at quanta
    crucible-api       versioned programmatic surface (session lifecycle, query)
    crucible-daemon    long-lived host process hosting sessions over the API
    crucible-cli       the `crucible` binary; thin client over crucible-api
    crucible-s3-store  bounded AWS SDK adapter for campaign object storage

  L3  ENGINE
    crucible           scenario model, the single scheduler, faults, assertions,
                       temporal graph, event log; the pure reduction
    crucible-cas       standalone content-addressed store, fleet store, and
                       campaign-continuity substrate
    crucible-campaign  portable campaign model, repository, and service contracts

  L2  QEMU INTEGRATION
    crucible-qemu        host-side launch/control of QEMU; concrete VM driver
    crucible-qemu-plugin in-VM cdylib (-plugin); owns virtual-time control + hooks
    crucible-guest       OPTIONAL in-guest white-box agent (doorbell client)
    crucible-debug-gateway mediated debugger transport without scheduler authority
    crucible-linux-resource pinned Linux quota/cgroup resource capabilities

  L1  CO-SIM TRANSPORT
    crucible-shmem     the public #[repr(C)] shared-memory process protocol
    crucible-protocol  the IPC wire protocol (framing, versioning, golden vectors)
    crucible-device    disk / 9p / net I/O sub-nodes (deterministic completion)

  L0  DETERMINISTIC CORE
    crucible-sim       deterministic runtime/scheduler primitives (seeded RNG,
                       ordered collections, deterministic select, content hash)
    crucible-assert    the assertion vocabulary types (Always/Sometimes/...)
```

One-line responsibilities:

| Layer | Crate | Responsibility (one line) |
| --- | --- | --- |
| L0 | `crucible-sim` | Deterministic runtime/scheduler primitives: seeded decision RNG, ordered collections, deterministic `select`, content-hashing — the substrate every higher layer must use. |
| L0 | `crucible-assert` | The assertion vocabulary *types* — `Always`/`Sometimes`/`Eventually`/`AfterQuiescence`/`Reachable` and their (de)serialization — with no evaluation engine. |
| L1 | `crucible-shmem` | The public `#[repr(C)]` shared-memory process protocol (per-node clocks, status, SPSC frame queues), with generated language views and golden vectors. |
| L1 | `crucible-protocol` | The host↔plugin IPC protocol: message framing, explicit version field, encode/decode, golden vectors. |
| L1 | `crucible-device` | Disk (CoW overlay), 9p (read-only, path-hashed QIDs), and net-link I/O sub-nodes with deterministic completion events. |
| L2 | `crucible-qemu` | Host-side QEMU process launch/control and the concrete VM driver wrapped by higher layers. |
| L2 | `crucible-qemu-plugin` | The in-VM `cdylib` loaded via `-plugin`; owns virtual-time control (`qemu_plugin_request_time_control`) and the device/channel callbacks. |
| L2 | `crucible-guest` | OPTIONAL in-guest agent for white-box markers via the doorbell; never required for any core capability (`G-3`). |
| L2 | `crucible-debug-gateway` | Mediated debugger transport and capability checks without scheduler or campaign authority. |
| L2 | `crucible-linux-resource` | Pinned Linux kernel resource capabilities shared by host-side QEMU and daemon composition. |
| L3 | `crucible` | The engine: scenario model, the single authoritative scheduler, fault injection, assertion evaluation, temporal graph, event log — the pure `reduce`. |
| L3 | `crucible-cas` | The standalone content-addressed store, fleet-visible DAG store, and campaign-continuity substrate. |
| L3 | `crucible-campaign` | RFC-0019's portable campaign model, authenticated repository, and component-message contracts. |
| L4 | `crucible-session` | The session actor: owns one live `RuntimeState`, drives the engine quantum loop, services control messages at quantum boundaries. |
| L4 | `crucible-api` | The versioned programmatic API surface (session lifecycle, stepping, event-log query, temporal-graph ops). |
| L4 | `crucible-daemon` | The long-lived host process that hosts sessions and serves the API over a transport. |
| L4 | `crucible-cli` | The `crucible` binary: a thin client over `crucible-api`; scenario authoring, run, reproduce, query. |
| L4 | `crucible-s3-store` | The bounded AWS SDK implementation of campaign object-store capabilities. |

### The dependency graph (acyclic; lower layers never depend on higher)

```text
                        crucible-cli ─────────────┐
                              │                    │
                        crucible-daemon            │
                              │                    │
                        crucible-api               │
                              │                    │
                        crucible-session           │  (all L4 → crucible-api)
                              │                    │
   ──────────────────────────┼────────────────────┘
                              ▼
                          crucible            (L3 engine)
                         /    │    \
                        /     │     \
        crucible-qemu         │      └► (engine uses VM drivers only via
              │               │           Backend trait adapters declared
              ▼               ▼           outside lower-layer crates)
        crucible-device  crucible-protocol
              │               │
              └──────┬────────┘
                     ▼
               crucible-shmem            (L1 ABI)
                     │
        ─────────────┼─────────────
                     ▼
            crucible-sim   crucible-assert     (L0 core)

   crucible-qemu-plugin (L2 cdylib)  ── depends on ──► crucible-shmem,
                                                       crucible-protocol  (L1 only)
   crucible-guest       (L2 agent)   ── depends on ──► crucible-shmem      (L1 only)
```

The QEMU-loaded plugin's **internal Crucible dependencies are only the
dual-licensed L1 boundary crates** (the ABI + protocol), never the engine. Its
external production dependency graph is separately checked for a
GPL-2.0-compatible license choice. The optional guest crate uses only its
versioned boundary protocol. They run inside
a different address space (or process) and must share *only* the wire/memory
contract. The host-side `crucible-qemu` is the sole L2 exception: it may depend
on `crucible` to implement the concrete host adapter for the engine `Backend`
trait and QEMU realization flow, but no in-VM crate may do so and no other
upward edge is allowed. The layer lint encodes this named exception.

- **[CRATE-1]** The AOS Rust workspace's Crucible package set MUST contain
  exactly the eighteen runtime crates above, partitioned into the five layers
  L0–L4 as listed. Pre-existing non-Crucible `aos-*` workspace members are outside
  this count. *Gate:* `gate:harness-lint` (workspace-shape lint). *Spec:* §1.
- **[CRATE-2]** Each crate MUST depend only on crates in its own layer or a lower
  layer; there MUST be no upward dependency and no dependency cycle. The rule is
  enforced by a CI lint that reads each crate's `[dependencies]` and rejects any
  edge that points to a higher layer or forms a cycle. *Gate:* `gate:harness-lint`.
  *Satisfies* `ARCH-3`, `G-5`. *Spec:* §1, [`03-architecture-overview.md`](03-architecture-overview.md) §4.
- **[CRATE-3]** The two in-VM L2 crates (`crucible-qemu-plugin`, `crucible-guest`)
  MUST depend only on L1 crates (and L0 transitively through them); they MUST NOT
  depend on `crucible` (L3) or any L4 crate, so the in-VM code shares only the
  versioned ABI/protocol. *Gate:* `gate:harness-lint`, `gate:abi-conformance`.
  *Satisfies* `G-8`. *Spec:* §1.

## 2. The crate-level safe/unsafe fence

Crucible mirrors the sibling RFC-0007 (`ratchet`) crate-level fence: the
safe/unsafe boundary is drawn *between crates*, not between modules inside one
crate. A crate either forbids `unsafe` entirely or permits it under the per-block
`// SAFETY:` discipline. A reviewer reads one crate-root attribute and knows the
regime that applies to every line in that crate — there is no file-by-file
ambiguity. This is what lets the engine be a genuinely `miri`-clean, sanitizer-
clean island (it is its own crate) rather than a hopefully-clean subtree of a
crate that also mmaps shared memory.

**SAFE crates** carry `#![forbid(unsafe_code)]` at the crate root. **UNSAFE
crates** carry `#![deny(unsafe_op_in_unsafe_fn)]` (every `unsafe` operation,
even inside an `unsafe fn`, must sit in an explicit `unsafe { }` block) and a
standing project waiver to use `unsafe` under the per-block `// SAFETY:`
discipline of [`28-engineering-standards.md`](28-engineering-standards.md).

| Crate | Fence | Why |
| --- | --- | --- |
| `crucible-sim` | **SAFE** `#![forbid(unsafe_code)]` | Pure deterministic primitives; no FFI, no raw memory. |
| `crucible-assert` | **SAFE** | Plain data types + serde; no FFI. |
| `crucible-shmem` | **UNSAFE** `#![deny(unsafe_op_in_unsafe_fn)]` | `mmap` of the shared region, `#[repr(C)]` field access across the boundary, lock-free SPSC atomics. |
| `crucible-protocol` | **UNSAFE** | Byte (de)serialization is pure, but `Setup` descriptor handover uses Unix `sendmsg`/`recvmsg` and `SCM_RIGHTS` ancillary buffers. |
| `crucible-device` | **SAFE** | Pure I/O-sub-node models over owned buffers / CoW page maps. |
| `crucible-qemu` | **UNSAFE** | Host-side process control may touch FFI for QMP/monitor and shared-memory file descriptors; reads raw VM memory via the plugin transport. |
| `crucible-qemu-plugin` | **UNSAFE** | The `cdylib` is the QEMU TCG plugin C ABI: `extern "C"` entry points, raw QEMU/guest memory, time-control FFI. |
| `crucible-debug-gateway` | **SAFE** | Mediated debugger protocol and process orchestration use safe owned capabilities. |
| `crucible-guest` | **UNSAFE** | The in-guest agent issues the trapped doorbell instruction and touches the shmem ABI directly; bare-metal/no-std-ish concerns. |
| `crucible-linux-resource` | **UNSAFE** | Narrow raw Linux quota/cgroup syscall wrappers validate pinned kernel-resource identities. |
| `crucible` | **SAFE** `#![forbid(unsafe_code)]` | The engine is a pure reduction; it must be a clean island. All unsafe is *below* it behind traits. |
| `crucible-cas` | **SAFE** | Content-addressed store and fleet/campaign data structures; no raw memory or FFI. |
| `crucible-campaign` | **SAFE** | Portable canonical campaign state and authenticated repository logic. |
| `crucible-session` | **SAFE** | Actor over channels; no raw memory. |
| `crucible-api` | **SAFE** | Versioned API types + dispatch. |
| `crucible-daemon` | **SAFE** | Host process; transport via safe libraries. |
| `crucible-cli` | **SAFE** | Thin client. |
| `crucible-s3-store` | **SAFE** | Bounded SDK adapter over owned buffers and async operations. |

So: **six UNSAFE crates** (`crucible-shmem`, `crucible-protocol`,
`crucible-qemu`, `crucible-qemu-plugin`, `crucible-guest`,
`crucible-linux-resource`) — exactly the crates
that touch raw QEMU/guest memory, the mmap/atomics ABI, Unix descriptor
handover, kernel resource syscalls, or FFI — and **twelve SAFE crates**,
including the entire engine and the entire control plane. The unsafe surface is
small, named, and confined to L1/L2.

- **[CRATE-4]** Every SAFE crate (`crucible-sim`, `crucible-assert`,
  `crucible-device`, `crucible-debug-gateway`, `crucible`, `crucible-cas`,
  `crucible-campaign`, `crucible-session`, `crucible-api`, `crucible-daemon`,
  `crucible-cli`, `crucible-s3-store`) MUST carry
  `#![forbid(unsafe_code)]` at its crate root. A CI lint asserts the attribute is
  present. *Gate:* `gate:harness-lint`. *Spec:* §2.
- **[CRATE-5]** Every UNSAFE crate (`crucible-shmem`, `crucible-protocol`,
  `crucible-qemu`, `crucible-qemu-plugin`, `crucible-guest`,
  `crucible-linux-resource`) MUST carry
  `#![deny(unsafe_op_in_unsafe_fn)]` at its crate root, and every `unsafe` block
  MUST be preceded by a `// SAFETY:` comment stating the upheld invariant. There
  MUST be no sixth UNSAFE crate: any new use of `unsafe` outside these five is a
  build error. *Gate:* `gate:harness-lint`. *Satisfies* `INV-9`. *Spec:* §2.

## 3. Crate boundaries — what each owns, and what it does NOT

The boundaries are chosen so that the determinism contract is structural. Each
entry states the crate's responsibility and, critically, its *anti-scope*.

### L0 — deterministic core

**`crucible-sim`** owns the determinism substrate: the seeded **decision RNG**
(per-entity streams forked by name-hash so adding a node does not perturb
others, [`04-determinism-contract.md`](04-determinism-contract.md)), ordered
collections (a `DetMap`/`DetSet` whose iteration order is content-defined, never
hash-random), a **deterministic `select`** over ready inputs (fixed tie-break,
not source-order or arrival-race), virtual-time arithmetic primitives
(icount↔ns, [`09-virtual-time-icount.md`](09-virtual-time-icount.md)), and the
canonical content-hash function (`INV-6`). It owns *no* policy: it knows nothing
of scenarios, nodes, QEMU, or faults. *Not in it:* the scheduler algorithm
(that is L3, built *on* these primitives), any I/O, any wall-clock.

**`crucible-assert`** owns the assertion *vocabulary as data*: the five property
kinds and their parameters, serde, and content hashing. *Not in it:* the
*evaluation* of assertions against an event log (that is the engine, L3), and
the event-log schema itself (L3).

### L1 — co-sim transport

**`crucible-shmem`** owns the `#[repr(C)]` shared-memory layout — the
**mechanically checked implementation schema for a public process protocol**
([`13-shmem-abi.md`](13-shmem-abi.md)). It defines the region header (per-node
clocks, status words), the SPSC ring buffers, the `FrameEntry` layout, the
version constant, and the `unsafe` accessors that map and read/write the region.
The C side of the QEMU patch series is generated from / checked against these
definitions (a `cbindgen`-style header emit + the `gate:abi-conformance` golden
vectors). *Not in it:* any message *semantics* or framing (that is
`crucible-protocol`), any scheduling, any QEMU process control.
It is `MIT OR Apache-2.0`, contains no QEMU dependency or header, and may expose
only protocol-shaped values allowed by 37/[BOUND-6].

**`crucible-protocol`** owns the IPC **wire protocol**
([`14-protocol.md`](14-protocol.md)): message kinds, framing, the explicit
version field, encode/decode, setup descriptor handover, and the golden-vector
corpus. It is an unsafe-boundary crate only for the Unix `SCM_RIGHTS`
`sendmsg`/`recvmsg` edge; the frame codec itself remains pure and operates over
owned byte buffers. *Not in it:* shmem mapping (that is `crucible-shmem`), QEMU
process control (that is `crucible-qemu`), or the meaning of a delivered frame
to the scheduler (L3).
It is `MIT OR Apache-2.0` and contains no QEMU implementation dependency.

**`crucible-device`** owns the **I/O sub-nodes**
([`15-io-subnodes.md`](15-io-subnodes.md)): the disk model (CoW overlay over a
read-only base, `INV-5`), the read-only 9p server (path-hashed QIDs, sorted
directory enumeration), and the net-link model (latency, loss applied by the
fault table). Each computes a **deterministic completion time** from the request
and a fixed model. *Not in it:* *when* completions are resolved relative to other
nodes (the scheduler, L3, resolves them in total order), and the actual disk
bytes' transport into the VM (the plugin/shmem path).

### L2 — QEMU integration

**`crucible-qemu`** owns **host-side QEMU**: building the argv (`-icount
shift=N`, `-plugin`, `-smp 1`, sealed-entropy flags), launching and supervising
the process, mapping the shmem region, and exposing a concrete host-driver API
that can advance a VM, read its fingerprint, snapshot, and restore it. The
engine-facing `Backend` trait remains in `crucible` (`CRATE-6`) and is adapted by
higher-layer wiring that may depend on both crates; the current host driver crate
is allowed to carry that `crucible-qemu` → `crucible` adapter edge, but the
exception is confined to host-side QEMU and never applies to the in-VM crates.
*Not in it:* scheduler policy, decision-making about *which* node to advance
(all L3); the in-VM time-control logic (that is the plugin).

**`crucible-qemu-plugin`** owns the **in-VM `cdylib`**
([`12-qemu-plugin.md`](12-qemu-plugin.md)): the QEMU TCG plugin `extern "C"`
entry points, virtual-time control via `qemu_plugin_request_time_control`
(suppressing warp), the per-TB/exec callbacks that drive the shmem clock and feed
basic-block coverage, and the device/channel callbacks. It is built as a separate
`cdylib` artifact loaded by QEMU. *Not in it:* host policy of any kind; it is a
mechanism that the host (`crucible-qemu`) configures over the ABI.
Because it loads into QEMU and calls QEMU APIs, it is GPL-2.0-only and may depend
only on GPL-compatible code, including the dual-licensed L1 boundary crates.

**`crucible-guest`** owns the **OPTIONAL** white-box agent
([`16-guest-host-channel.md`](16-guest-host-channel.md)): a tiny in-guest client
that emits markers/assertions by triggering the doorbell. It is strictly
additive (`G-3`, `ARCH-8`): nothing in L3/L4 may *require* it. *Not in it:* any
core capability; black-box observation must suffice without it.

### L3 — engine

**`crucible`** owns everything that makes a run a pure reduction: the scenario
model surface (the in-engine view of `ScenarioDef`,
[`06-spatial-graph.md`](06-spatial-graph.md)), the **single authoritative
scheduler** (the quantum loop, horizon/lookahead, the total order `(virtual_time,
consumer node_id, producer node_id, sequence)`,
[`08-scheduling.md`](08-scheduling.md)), fault injection
([`17-fault-injection.md`](17-fault-injection.md)), assertion *evaluation* over the
event log ([`18-assertions-properties.md`](18-assertions-properties.md)), the
**temporal graph** (checkpoint DAG, CoW, the replay oracle,
[`07-temporal-graph.md`](07-temporal-graph.md)), the **event log**
([`19-observability-event-log.md`](19-observability-event-log.md)), and the
`step`/`reduce`/`instantiate`/`bake` functions
([`05-execution-model.md`](05-execution-model.md)).

The engine has **no QEMU knowledge**: it talks to L2 only through a `Backend`
trait (`CRATE-6`) that it declares itself. The concrete QEMU driver lives in
`crucible-qemu`; a higher-layer adapter wraps that driver in the engine trait
without adding a lower-to-higher Cargo edge. An in-process test double lives
behind the same trait (§4, `CRATE-7`). This is the load-bearing boundary: it is
*why* `crucible` can be `#![forbid(unsafe_code)]` and `miri`-clean, and *why*
`gate:layer0-determinism` and the engine-level gates can run with no QEMU
present.

**`crucible-campaign`** owns RFC-0019's portable, content-addressed campaign
model, component-message contracts, authenticated repository, and deterministic
planning semantics. It depends on the L3 content store but contains no live
process handles or QEMU-private state. The L4 daemon composes it with local
executor and QEMU adapters.

- **[CRATE-6]** The engine (`crucible`) MUST interact with any VM backend solely
  through a `Backend` trait that it declares; the engine MUST NOT name
  `crucible-qemu`, `qemu`, or any process/FFI type in its public or private API.
  The trait abstracts: advance-to-horizon, read execution fingerprint, deliver an
  input, snapshot, restore, and shutdown. *Gate:* `gate:harness-lint`,
  `gate:layer0-determinism`. *Satisfies* `ARCH-3`, `G-5`, `G-8`. *Spec:* §3, §4.

### L4 — control plane

**`crucible-session`** owns the **session actor**
([`20-session-control-plane.md`](20-session-control-plane.md)): it holds one live
`RuntimeState` and the engine, runs the quantum loop, and services control
messages (pause/resume/step/snapshot/fork/query) at quantum boundaries (`INV-8`,
`ARCH-9`). Control is messages to an actor, never shared-state mutation. *Not in
it:* the scheduler algorithm (it *drives* the engine's loop; it does not
re-implement it).

**`crucible-api`** owns the **versioned programmatic surface**
([`21-api.md`](21-api.md), `G-8`): session lifecycle, stepping modes, the
event-log query interface, and temporal-graph operations, with an explicit
version field and conformance vectors. *Not in it:* any policy or scheduling; it
is the contract between client and daemon. Its lifecycle adapter may implement
and drive the public L3 `QuantumLoop` boundary, including the deterministic
quiescent test loop and production lifecycle wrapper, but it does not own or
reimplement scheduler ordering policy.

**`crucible-daemon`** owns the **long-lived host process** that hosts sessions,
serves `crucible-api` over a transport, and composes host-side executor workers
that drive the L3 `QuantumLoop` boundary without owning scheduler policy. RFC-0019
adds the campaign coordinator and local executor composition to this crate. *Not
in it:* the API *definition* (that's `crucible-api`), canonical campaign state
(that's `crucible-campaign`), scheduler algorithms, or the CLI.

**`crucible-cli`** owns the **`crucible` binary**: scenario authoring helpers,
`run`/`reproduce`/`query`/`fork`/`search` subcommands ([`23-cli.md`](23-cli.md)),
talking to the daemon (or an embedded session) over `crucible-api`. It is a thin
client; it owns no algorithms.

- **[CRATE-8]** The CLI (`crucible-cli`) MUST reach lower-layer execution only
  through `crucible-api`, `crucible-session`, `crucible-campaign`, or the
  packaged `crucible-daemon` composition. The daemon MAY depend on lower-layer
  host crates and drive the public L3 `QuantumLoop` boundary for an admitted
  attempt, but MUST NOT reimplement scheduler policy or call private reduction
  internals. *Gate:* `gate:control-responsive`. *Satisfies* `INV-8`, `ARCH-9`.
  *Spec:* §3 and RFC-0019 file 04a.

## 4. Feature flags — the backend trait and the in-process double

The single most important seam is the `Backend` trait (`CRATE-6`). It has a
production-safe local implementation and a feature-gated shared-memory test
double so that the engine's own test suites need no QEMU:

- The **real QEMU driver** (`crucible-qemu`) drives a patched QEMU process.
- The **in-process double** (`SimBackend`) is a deterministic model of a VM-like
  node — it advances an icount, returns a deterministic fingerprint, accepts
  delivered inputs, and snapshots/restores its small state — entirely in SAFE
  Rust, with no QEMU. It is the harness companion to `gate:layer0-determinism`
  and the engine-level scheduler/temporal-graph gates, letting them run fast and
  hermetically on every PR (it is *not* the in-process testing of host services
  forbidden by `NG-2`; it is a test double behind the backend trait).

Feature layout:

```toml
# crucible (the L3 engine) Cargo.toml — features
[features]
default = []
# Compile the shared-memory plugin-side SimDouble used by focused integration
# gates. The production-safe SimBackend remains available without this feature.
test-double = ["dep:crucible-shmem"]
```

```toml
# crucible-device ships one uniform I/O model; no inert feature labels.
[features]
default = []
```

```toml
# crucible-guest is OPTIONAL at the workspace level: it is an opt-in
# white-box agent, never pulled by any core crate (G-3, ARCH-8).
```

- **[CRATE-7]** The engine MUST provide a `test-double` feature that compiles an
  in-process, SAFE-Rust `SimBackend` implementing the `Backend` trait of
  `CRATE-6`, sufficient to run `gate:layer0-determinism`, `gate:replay-oracle`,
  and `gate:scheduler-liveness` with no QEMU present. The double MUST be
  deterministic by the same `crucible-sim` primitives the engine uses. *Gate:*
  `gate:layer0-determinism`, `gate:replay-oracle`. *Satisfies* `G-5`. *Spec:*
  §4, [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).
- **[CRATE-9]** Feature flags MUST be **additive** (purely additive cargo
  features, no mutually-exclusive flags that change default behavior); the
  `default` feature set MUST select a working configuration, and enabling any
  combination MUST compile. `crucible-guest` MUST NOT be a dependency of any
  default build of a core crate. *Gate:* `gate:harness-lint` (a `cargo
  hack`-style feature-powerset compile check). *Satisfies* `G-3`. *Spec:* §4.
- **[CRATE-10]** The `Backend` trait MUST be object-safe (usable as `dyn
  Backend`) OR selected by a single generic parameter threaded from the session,
  so the same engine code runs unchanged against `SimBackend` and the QEMU
  backend; there MUST NOT be two engine code paths. *Gate:* `gate:harness-lint`.
  *Satisfies* `ARCH-2`, `G-4`. *Spec:* §4.

## 5. The determinism boundary across crates

The determinism contract decomposes into crates that MUST be deterministic *by
construction* (and are gated for it) and crates that are *allowed* to be
nondeterministic because they are host-side diagnostics or process plumbing.

**MUST pass `gate:harness-lint` (deterministic engine, `INV-9`):** every crate
on the reduction path — `crucible-sim`, `crucible-assert`, `crucible`,
`crucible-protocol`, `crucible-device`, and the in-engine glue of
`crucible-session`. These crates MUST NOT: iterate an unordered map on an
ordering-significant path (use `crucible-sim`'s ordered collections), read the
host wall-clock, draw from a thread/global RNG, or use a nondeterministic
`select`. The lint is a `clippy`/custom-lint pass plus a deny-list of imports
(`std::time::SystemTime`, `Instant` on ordering paths, `rand::thread_rng`,
`HashMap`/`HashSet` iteration in the engine).

**Nondeterministic-allowed (host diagnostics / plumbing):** `crucible-daemon`
(it serves clients, logs with timestamps, schedules background work),
`crucible-cli` (it prints progress, reads the host clock for human-facing
output), and the host-supervision *non-reduction* parts of `crucible-qemu`
(process spawn timing, retry/backoff). These MUST keep their nondeterminism
**off the reduction path**: any value that influences `State` MUST flow through
the seeded decision source in `crucible-sim`, never from these crates. The
boundary is enforced by `CRATE-6`/`CRATE-8` (the engine cannot even *name* these
crates) plus the harness lint applied to the reduction-path crates only.

The two in-VM L2 crates are a special case: `crucible-qemu-plugin` and
`crucible-guest` are UNSAFE *and* on the determinism-critical path, but their
determinism is **Contract A** (intra-VM hermeticity), gated by
`gate:single-vm-fingerprint`, not by `gate:harness-lint` (which is a host-Rust
static lint). Their job is to *seal* entropy, and they are proven by the
execution-fingerprint gate, not by import-deny-listing.

- **[CRATE-11]** The reduction-path crates (`crucible-sim`, `crucible-assert`,
  `crucible`, `crucible-protocol`, `crucible-device`, `crucible-session`) MUST
  pass `gate:harness-lint`: no host wall-clock, no thread/global RNG, no
  unordered-map iteration on ordering-significant paths, deterministic `select`
  only. *Gate:* `gate:harness-lint`. *Satisfies* `INV-9`, `INV-10`. *Spec:* §5.
- **[CRATE-12]** Nondeterminism is permitted only in `crucible-daemon`,
  `crucible-cli`, and the non-reduction supervision code of `crucible-qemu`, and
  only off the reduction path: no value produced by host wall-clock, host RNG, or
  host-scheduling order in these crates MUST influence `State`. Any such value
  that *must* affect the run MUST be routed through the `crucible-sim` decision
  source. *Gate:* `gate:harness-lint`, `gate:adversarial-determinism`.
  *Satisfies* `INV-1`, `INV-9`. *Spec:* §5.

## 6. Mapping crates to spec files

Each crate is owned by, and implements, a definite slice of the spec. This table
is the bidirectional index: it tells an implementor which file defines a crate's
contract and which crate realizes a file.

| Crate | Owning RFC file(s) | Determinism gate(s) |
| --- | --- | --- |
| `crucible-sim` | [`04`](04-determinism-contract.md), [`08`](08-scheduling.md), [`09`](09-virtual-time-icount.md) | `gate:layer0-determinism`, `gate:harness-lint` |
| `crucible-assert` | [`18`](18-assertions-properties.md) | `gate:layer0-determinism`, `gate:harness-lint` |
| `crucible-shmem` | [`13`](13-shmem-abi.md) | `gate:abi-conformance`, `gate:license-boundary` |
| `crucible-protocol` | [`14`](14-protocol.md), [`16`](16-guest-host-channel.md) | `gate:abi-conformance`, `gate:harness-lint`, `gate:license-boundary` |
| `crucible-device` | [`15`](15-io-subnodes.md) | `gate:layer1-injection`, `gate:harness-lint` |
| `crucible-qemu` | [`10`](10-qemu-integration.md), [`11`](11-qemu-patches.md) | `gate:single-vm-fingerprint`, `gate:any-guest`, `gate:qemu-inert`, `gate:license-boundary` |
| `crucible-qemu-plugin` | [`11`](11-qemu-patches.md), [`12`](12-qemu-plugin.md) | `gate:single-vm-fingerprint`, `gate:patch-microtests`, `gate:license-boundary` |
| `crucible-debug-gateway` | [`36`](36-time-travel-debugging.md) | `gate:license-boundary` |
| `crucible-guest` | [`16`](16-guest-host-channel.md) | `gate:single-vm-fingerprint` (markers excluded from comparison) |
| `crucible` | [`05`](05-execution-model.md), [`06`](06-spatial-graph.md), [`07`](07-temporal-graph.md), [`08`](08-scheduling.md), [`17`](17-fault-injection.md), [`18`](18-assertions-properties.md), [`19`](19-observability-event-log.md) | `gate:replay-oracle`, `gate:content-address`, `gate:scheduler-liveness`, `gate:divergence-bisect`, `gate:checkpoint-materialization`, `gate:state-space-search`, `gate:signal-fault-system`, `gate:harness-lint` |
| `crucible-cas` | [`35`](35-distributed-continuous-exploration.md) | `gate:fleet-equivalence`, `gate:campaign-continuity`, `gate:content-address` |
| `crucible-session` | [`20`](20-session-control-plane.md) | `gate:control-responsive`, `gate:harness-lint` |
| `crucible-api` | [`21`](21-api.md) | `gate:abi-conformance`, `gate:control-responsive` |
| `crucible-daemon` | [`20`](20-session-control-plane.md), [`21`](21-api.md) | `gate:control-responsive` |
| `crucible-cli` | [`23`](23-cli.md) | `gate:e2e-determinism` (top-level) |

Cross-cutting concerns spread across crates: virtual time
([`09`](09-virtual-time-icount.md)) is *defined* in `crucible-sim` and *consumed*
by `crucible` and `crucible-qemu`; the determinism harness
([`24`](24-determinism-harness-testing.md)) is a test-only crate-spanning suite
(§7); packaging ([`26`](26-packaging-aos-integration.md)) wraps the whole
workspace and the AOS QEMU package; engineering standards
([`28`](28-engineering-standards.md)) apply to every crate.

- **[CRATE-13]** Every crate MUST carry a `//!` crate-level doc that names the
  RFC file(s) it implements (the rows above) so the spec↔code thread is navigable
  from the source, per [`28-engineering-standards.md`](28-engineering-standards.md).
  *Gate:* `gate:harness-lint` (doc lint). *Satisfies* `G-8`. *Spec:* §6.

## 7. Build and test layout

### Workspace root

A single AOS Rust workspace pins one toolchain, one dependency-version set, and
the per-layer lints. The Crucible package set is the subset of workspace members
listed below.

```toml
# Cargo.toml (workspace root) — illustrative
[workspace]
resolver = "2"
members = [
  # L0
  "crates/crucible-sim",
  "crates/crucible-assert",
  # L1
  "crates/crucible-shmem",
  "crates/crucible-protocol",
  "crates/crucible-device",
  # L2
  "crates/crucible-qemu",
  "crates/crucible-qemu-plugin",
  "crates/crucible-debug-gateway",
  "crates/crucible-guest",
  "crates/crucible-linux-resource",
  # L3
  "crates/crucible",
  "crates/crucible-cas",
  "crates/crucible-campaign",
  # L4
  "crates/crucible-session",
  "crates/crucible-api",
  "crates/crucible-daemon",
  "crates/crucible-cli",
  "crates/crucible-s3-store",
  # test-only harness (not a layer; spans crates)
  "crates/crucible-harness",
]

[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"   # UNSAFE crates re-affirm; SAFE crates forbid

[workspace.package]
edition = "2021"
# Individual packages declare Apache-2.0, MIT OR Apache-2.0, or GPL-2.0-only
# according to docs/legal/licensing.md and file 37.
```

`crucible-qemu-plugin` builds a `cdylib`; most crates build `lib`s.
`crucible-cli` builds the `crucible` binary, and `crucible-cas` builds the
supporting `crucible-fleet-store` binary:

```toml
# crates/crucible-qemu-plugin/Cargo.toml
[lib]
crate-type = ["cdylib"]

# crates/crucible-cli/Cargo.toml
[[bin]]
name = "crucible"
path = "src/main.rs"

# crates/crucible-cas/Cargo.toml
[[bin]]
name = "crucible-fleet-store"
path = "src/bin/crucible-fleet-store.rs"
```

There is a **nineteenth, test-only crate**, `crucible-harness` (not part of the
L0–L4 layering and not shipped), that hosts the cross-crate determinism gates of
[`24`](24-determinism-harness-testing.md): the execution-fingerprint comparator,
the divergence bisector, the replay-oracle checker, the ABI golden-vector runner,
and the adversarial-host driver. It is a dev-dependency-only member, so it never
enters a release build.

### Where tests live

- **Unit tests** live in-crate (`#[cfg(test)] mod tests`) and cover that crate's
  own contract.
- **Per-layer determinism gates** are integration tests (`tests/`) that map onto
  the gate names of [`24`](24-determinism-harness-testing.md):

| Gate | Lives in | Run as |
| --- | --- | --- |
| `gate:harness-lint` | `crucible-harness` + workspace `cargo` lints | every PR (Phase 0) |
| `gate:layer0-determinism` | `crucible-sim` `tests/`, `crucible-assert` `tests/`, `crucible` `tests/` (`--features test-double`) | reduce-twice equality |
| `gate:single-vm-fingerprint` | `crucible-qemu` + `crucible-qemu-plugin` `tests/` | one-VM fingerprint match |
| `gate:layer1-injection` | `crucible-device` + `crucible-protocol` `tests/` | injection-icount purity |
| `gate:abi-conformance` | `crucible-harness` golden vectors over `crucible-shmem`/`crucible-protocol`/`crucible-api` plus `crucible-qemu-plugin`/`crucible-guest` ABI tests | frozen golden vectors |
| `gate:typed-choice` | `crucible-campaign` `tests/gate_typed_choice.rs` plus the Phase-2 guest/protocol selectable suites | canonical typed domains, exact branch selection, and negative replay checks |
| `gate:license-boundary` | `crucible-harness` dependency/license/protocol/package checks | Always; every boundary change and release construction |
| `gate:replay-oracle` | `crucible` `tests/` (`--features test-double`) | fat-hash == thin-hash |
| `gate:content-address` | `crucible` + `crucible-sim` `tests/` | hash equality/collision |
| `gate:scheduler-liveness` | `crucible` `tests/` (`--features test-double`) | reaches quiescence/limit |
| `gate:control-responsive` | `crucible-session` + `crucible-api` `tests/` | bounded-quantum ack |
| `gate:any-guest` | `crucible-qemu` `tests/` (guest matrix) | unmodified-guest boot |
| `gate:qemu-inert` / `gate:patch-microtests` | AOS QEMU package tests ([`26`](26-packaging-aos-integration.md)) + `crucible-qemu-plugin` | sim-off identity; per-patch |
| `gate:divergence-bisect` | `crucible-harness` | first-differing-step localization |
| `gate:adversarial-determinism` | `crucible-harness` (host-hostile driver) | N-run byte-identical logs |
| `gate:e2e-determinism` | `crucible-harness` + `crucible-cli` (final acceptance) | full multi-VM reproduce |

- **[CRATE-14]** The Crucible package set MUST live in the single AOS virtual
  Cargo workspace that pins one toolchain and one dependency-version set. Within
  the Crucible package set, the only `cdylib` MUST be `crucible-qemu-plugin`, and
  the shipped Crucible binaries MUST be exactly `crucible` (from
  `crucible-cli`) and `crucible-fleet-store` (from `crucible-cas`).
  Pre-existing `aos-*` binaries are outside this Crucible binary count. *Gate:*
  `gate:harness-lint`. *Satisfies* `G-7`, `G-8`. *Spec:* §7.
- **[CRATE-15]** A test-only crate `crucible-harness` MUST host the cross-crate
  determinism gates (fingerprint comparator, divergence bisector, replay-oracle
  checker, ABI golden-vector runner, adversarial driver) and MUST be a
  dev-dependency-only member that never enters a release build. *Gate:*
  `gate:harness-lint`. *Satisfies* `G-5`. *Spec:* §7,
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).
- **[CRATE-16]** Each per-layer determinism gate MUST be realized as a named test
  target in the crate(s) of the table above, runnable in isolation, so a layer's
  gate is green before any higher layer's tests run (`G-5`, `ARCH-4`). The engine
  gates MUST run under `--features test-double` with no QEMU. *Gate:*
  `gate:layer0-determinism`, `gate:replay-oracle`, `gate:scheduler-liveness`.
  *Satisfies* `ARCH-4`, `G-5`. *Spec:* §7.
- **[CRATE-17]** The AOS-side build ([`26`](26-packaging-aos-integration.md)) MUST
  build the whole workspace hermetically from source with no upstream binary
  dependencies, and the `crucible-qemu-plugin` `cdylib` MUST be built against the
  AOS QEMU package's plugin headers. *Gate:* `gate:qemu-inert`, `gate:e2e-determinism`.
  *Satisfies* `G-7`. *Spec:* §7, [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md).

### Relationship to RFC-0007 (`ratchet`)

`ratchet` (RFC-0007) is an AOS sibling and conceptual cousin — both are
content-addressed, determinism-obsessed Rust graph-reduction workspaces with a
crate-level safe/unsafe fence — but it is **not a dependency** (`NG-7`). Crucible
mirrors ratchet's *crate-level fence convention* (one root attribute per crate,
no module-level ambiguity) but ships standalone. Any shared content-addressed-store
substrate is gated behind a future integration
([`26-packaging-aos-integration.md`](26-packaging-aos-integration.md) §"ratchet
gate"); until then `crucible-cas` carries the standalone content-addressed store
surface and marks the seam, while `crucible-sim` carries deterministic core
primitives.

- **[CRATE-18]** No Crucible crate MUST depend on any `ratchet-*` / `aos-nix-*`
  crate; the content-addressed store primitives Crucible needs MUST live in
  `crucible-cas` (marked as a candidate seam for a later ratchet integration).
  *Gate:* `gate:harness-lint`. *Satisfies* `NG-7`. *Spec:* §7, README §"Relationship
  to RFC-0007".

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are tracked
> here per [`00-conventions.md`](00-conventions.md) `[PLAN-3]`. They scaffold the
> workspace shape, the safe/unsafe fence, the backend seam, and the gate↔crate
> wiring so every later subsystem lands in a fixed frame.

- [x] **T-CRATE-1** Create the Crucible package-set skeleton in the AOS Cargo
  virtual workspace with the eighteen L0–L4 crates plus the test-only
  `crucible-harness`, each as an empty, compiling crate carrying its `//!` crate
  doc naming its owning RFC file(s). — satisfies [CRATE-1], [CRATE-13],
  [CRATE-14]; spec §1, §6, §7.
- [x] **T-CRATE-2** Apply the crate-level safe/unsafe fence: `#![forbid(unsafe_code)]`
  on the twelve SAFE crates, `#![deny(unsafe_op_in_unsafe_fn)]` on the six UNSAFE
  crates, with a CI lint asserting the attribute on every crate root. — satisfies
  [CRATE-4], [CRATE-5]; spec §2.
- [x] **T-CRATE-3** Implement the layer-dependency + acyclicity lint that reads
  each crate's `[dependencies]` and rejects upward edges or cycles, with the
  named host-side `crucible-qemu` → `crucible` adapter exception and the
  L2-in-VM-crates-depend-only-on-L1 rule. — satisfies [CRATE-2], [CRATE-3];
  spec §1.
- [x] **T-CRATE-4** Declare the `Backend` trait in `crucible` (advance-to-horizon,
  fingerprint, deliver-input, snapshot, restore, shutdown), object-safe or single
  generic, with no QEMU/FFI types named in the engine. — satisfies [CRATE-6],
  [CRATE-10]; spec §3, §4.
- [x] **T-CRATE-5** Implement the in-process `SimBackend` in SAFE Rust,
  deterministic via `crucible-sim`, sufficient to run the engine determinism
  gates with no QEMU; keep only the shared-memory `SimDouble` behind
  `test-double`. — satisfies [CRATE-7];
  spec §4.
- [x] **T-CRATE-6** Establish the additive feature-flag layout (the consumed
  `test-double` and QEMU `test-support` gates; optional `crucible-guest`)
  and a feature-powerset compile check; verify every default works and
  `crucible-guest` is never a default core dependency. — satisfies [CRATE-9];
  spec §4.
- [x] **T-CRATE-7** Wire `gate:harness-lint` over the reduction-path crates: deny
  host wall-clock, thread/global RNG, unordered-map iteration on ordering paths,
  and nondeterministic `select`. — satisfies [CRATE-11]; spec §5.
- [x] **T-CRATE-8** Confine nondeterminism to `crucible-daemon`, `crucible-cli`,
  and `crucible-qemu` supervision code, with a check that no value from these
  reaches `State` except via the `crucible-sim` decision source. — satisfies
  [CRATE-12]; spec §5.
- [x] **T-CRATE-9** Enforce the control-plane boundary: `crucible-cli` reaches
  execution through the API/session/campaign/daemon composition, while
  `crucible-daemon` may drive only the public L3 quantum-loop boundary and never
  owns scheduler policy or private reduction internals. — satisfies [CRATE-8];
  spec §3 and RFC-0019 file 04a.
- [x] **T-CRATE-10** Configure crate artifact types: `crucible-qemu-plugin` as the
  sole `cdylib`, `crucible-cli` as `[[bin]] name = "crucible"`, `crucible-cas` as
  `[[bin]] name = "crucible-fleet-store"`, and the rest as libs. — satisfies
  [CRATE-14]; spec §7.
- [x] **T-CRATE-11** Stand up the `crucible-harness` test crate hosting the
  cross-crate gates (fingerprint comparator, divergence bisector, replay-oracle
  checker, ABI golden-vector runner, adversarial driver) as a dev-dependency-only
  member. — satisfies [CRATE-15]; spec §7.
- [x] **T-CRATE-12** Map each per-layer determinism gate to a named, isolable test
  target in its owning crate(s) per the §7 table; run the engine gates under
  `--features test-double`. — satisfies [CRATE-16], [CRATE-7]; spec §7.
- [x] **T-CRATE-13** Author the crate→spec-file index (the §6 table) into each
  crate's `//!` doc and a workspace-level doc lint that keeps it in sync. —
  satisfies [CRATE-13]; spec §6.
- [x] **T-CRATE-14** Build the whole workspace hermetically from source inside AOS,
  compiling `crucible-qemu-plugin` against the AOS QEMU package's plugin headers,
  with no upstream binary dependency. — satisfies [CRATE-17]; spec §7,
  [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md).
- [x] **T-CRATE-15** Add a lint forbidding any dependency on `ratchet-*` /
  `aos-nix-*`, and locate the content-addressing primitives in `crucible-sim`
  marked as the future-ratchet-integration seam. — satisfies [CRATE-18]; spec §7.
- [x] **T-CRATE-16** Remove the test-only surface from the production dependency
  graph: no shipped crate may depend on `crucible` with the `test-double`
  feature, and no feature may be declared without a `cfg` that consumes it.
  — satisfies [CRATE-11], [CRATE-12]; spec §5.
  - Defect (audit 2026-07-28): `crucible-api`, `crucible-daemon`, and
    `crucible-qemu` each depend on `crucible` with `features = ["test-double"]`
    outside `[dev-dependencies]`, so the in-process double is compiled into the
    shipped closure and is reachable from production code paths. Separately
    `crates/crucible/Cargo.toml` declares `qemu-backend = []` and no
    `#[cfg(feature = "qemu-backend")]` exists anywhere in the workspace — the
    feature is a label that suggests a compile-time backend split that does not
    exist.
  - Plan: (1) move the `test-double` feature edges into `[dev-dependencies]`,
    splitting any production type that currently sits behind the feature into a
    non-test module; (2) either implement the `qemu-backend` split behind real
    `cfg` gates or delete the feature; (3) add a workspace lint asserting that
    every declared feature is referenced by at least one `cfg`.
  - Gate: extend `checks.crucible.phase1.crateFeaturePowerset` to build the
    shipped feature set with `test-double` disabled and fail if any production
    crate requires it.
  Completed by `checks.crucible.phase1.crateFeaturePowerset`: `SimBackend` is
  now an always-available local backend while the shmem-backed `SimDouble`
  remains behind `crucible/test-double`; shipped crates use plain `crucible`,
  and the live QEMU comparison examples opt into a consumed
  `crucible-qemu/test-support` feature. The Nix and Rust mirrors reject any
  production dependency that enables `test-double`, exercise the production
  no-default-feature build, and reject declared features with no consuming
  `cfg`.
