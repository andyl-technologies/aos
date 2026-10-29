# Crate structure

Crucible is a set of Cargo packages under `crates/crucible/` in the AOS Rust
workspace (`crates/Cargo.toml`). The packages form five layers, L0 to L4, plus
the test-only `crucible-test-support`. The layering is the physical form of the
determinism contract: the engine cannot read a wall clock or touch raw guest
memory because the crates that can do those things sit below it, behind
traits, and outside its dependency set. A reviewer reads one crate-root
attribute and one `[dependencies]` table and knows which rules apply to every
line in that crate.

Every rule on this page is enforced by an integration test in
`crates/crucible/crucible-test-support/tests/`, mirrored by a Nix check under
`checks.crucible.phase1`. Changing the crate set, a dependency edge, a crate
fence, a feature, or an artifact type means updating the executable list in
the matching test in the same change. The architecture overview is in
[architecture.md](architecture.md); the gates each crate owns are in
[testing-and-gates.md](testing-and-gates.md).

## Crate map

```text
  L4  CONTROL PLANE
    crucible-session          live session actor; control at quantum boundaries
    crucible-control-api      native versioned control contracts and encodings
    crucible-control-client   HTTP/2 and in-process clients over the contract
    crucible-control-server   session dispatch and HTTP/2 server
    crucible-daemon           long-lived host process; production VM lifecycles
    crucible-cli              the `crucible` binary
    crucible-store-s3         AWS SDK transport for S3-compatible object storage

  L3  ENGINE
    crucible-engine           scenario model, scheduler, faults, assertions,
                              temporal graph, event log; the pure reduction
    crucible-store            content-addressed store, fleet store, invalidation
    crucible-campaign         portable campaign identities and contracts

  L2  QEMU INTEGRATION
    crucible-qemu-host        host-side QEMU launch, supervision, QMP, backend
    crucible-qemu-plugin      in-VM cdylib loaded by QEMU (-plugin)
    crucible-guest            optional in-guest white-box emitter
    crucible-qemu-debug-gateway  GPL-side debugger gateway process

  L1  CO-SIM TRANSPORT
    crucible-qemu-shmem       public shared-memory process ABI
    crucible-qemu-protocol    public host/plugin process protocol
    crucible-device           disk, 9p, and network-link I/O sub-nodes

  L0  DETERMINISTIC CORE
    crucible-determinism      seeded decision streams, ordered collections,
                              deterministic selection, virtual-time arithmetic,
                              content-addressing primitives

  --  TEST ONLY
    crucible-test-support     gate catalog, harness components, workspace lints
```

The layer of each package is the `LayerSpec` list in
`tests/crate_layer_graph.rs`. The artifact column is checked by
`tests/crate_artifact_types.rs`, the fence by `tests/crate_unsafe_fence.rs`,
and the license comes from each `Cargo.toml` (`license.workspace = true`
resolves to `Apache-2.0`).

| Layer | Crate | Artifact | License | Fence | Responsibility |
| --- | --- | --- | --- | --- | --- |
| L0 | `crucible-determinism` | lib | Apache-2.0 | safe | Seeded decision streams, ordered collections, deterministic selection, virtual-time arithmetic, content-addressing primitives; no QEMU, transport, scheduler policy, or wall clock. |
| L1 | `crucible-qemu-shmem` | lib | MIT OR Apache-2.0 | unsafe boundary | The versioned shared-memory process ABI declared by `interface/crucible-shmem-abi.toml`: region layout, SPSC frame rings, generated C header. See [shmem-abi.md](shmem-abi.md). |
| L1 | `crucible-qemu-protocol` | lib | MIT OR Apache-2.0 | unsafe boundary | Framing, versioned codecs, and golden vectors over owned buffers; setup descriptor handover over Unix `SCM_RIGHTS`. See [control-protocol.md](control-protocol.md). |
| L1 | `crucible-device` | lib | Apache-2.0 | safe | Disk, 9p, and network-link models as uniform scheduling sub-nodes with deterministic completion. See [io-subnodes.md](io-subnodes.md). |
| L2 | `crucible-qemu-host` | lib | Apache-2.0 | unsafe boundary | QEMU argv construction and validation, child supervision, shared-memory mapping, QMP, and the engine backend adapter. See [qemu-integration.md](qemu-integration.md). |
| L2 | `crucible-qemu-plugin` | `cdylib` | GPL-2.0-only | unsafe boundary | The plugin loaded into QEMU: plugin entry points, virtual-time control, device and channel callbacks. See [qemu-plugin.md](qemu-plugin.md). |
| L2 | `crucible-guest` | lib + bin `crucible-guest` | Apache-2.0 | unsafe boundary | Optional in-guest emitter for white-box markers over the doorbell; never required by a core capability. See [guest-host-channel.md](guest-host-channel.md). |
| L2 | `crucible-qemu-debug-gateway` | lib + bin `crucible-debug-gateway` | GPL-2.0-only | safe | Separate debugger gateway process over the owned-byte debug protocol and QEMU's RSP endpoint. See [time-travel-debugging.md](time-travel-debugging.md). |
| L3 | `crucible-engine` | lib | Apache-2.0 | safe | Execution-model vocabulary, the single scheduler, temporal graph, faults, assertions, event log, and the backend traits. See [execution-model.md](execution-model.md). |
| L3 | `crucible-store` | lib + bin `crucible-fleet-store` | Apache-2.0 | safe | BLAKE3 content keys, a `put`/`get`/`has` store with local, in-memory, and fleet-shared implementations, and dependency-gated invalidation. |
| L3 | `crucible-campaign` | lib | Apache-2.0 | safe | Immutable, content-addressed campaign identities, facts, planning state, and component contracts. |
| L4 | `crucible-session` | lib | Apache-2.0 | safe | `SessionDriver`, `Engine`, and `SessionActor`: one live runtime state driven at quantum boundaries. See [session.md](session.md). |
| L4 | `crucible-control-api` | lib | Apache-2.0 | safe | Transport-independent control contracts, frozen RPC encodings, and compatibility rules; starts no server or actor. See [control-api.md](control-api.md). |
| L4 | `crucible-control-client` | lib | Apache-2.0 | safe | Typed request dispatch and stream receivers over HTTP/2 and in-process transports. |
| L4 | `crucible-control-server` | lib | Apache-2.0 | safe | Actor registries, lifecycle dispatch, streams, and the HTTP/2 and TLS server. |
| L4 | `crucible-daemon` | lib | Apache-2.0 | safe | The long-lived host process: hosts sessions and composes production VM lifecycles over the server and QEMU host libraries. |
| L4 | `crucible-cli` | bin `crucible` | Apache-2.0 | safe | The `crucible` command: argument dispatch over the control, session, and campaign APIs. See [cli.md](cli.md). |
| L4 | `crucible-store-s3` | lib | Apache-2.0 | safe | A bounded command queue on a dedicated Tokio runtime implementing the store's S3-compatible immutable leaf. |
| test | `crucible-test-support` | lib | Apache-2.0 | safe | Gate catalog, ordering, harness components, and the workspace lints. |

Every package sets `publish = false` and `[lints] workspace = true`. The
license split follows [../../legal/licensing.md](../../legal/licensing.md):
code loaded into QEMU or speaking QEMU's internal protocols is GPL-2.0-only,
the two public process protocols are permissively dual-licensed so either
side can implement them independently, and the rest of the host is Apache-2.0.

Both `tests/crate_layer_graph.rs` and the spec-index and fence tests first
compare the set of `crucible*` package directories with their expected list,
so adding or removing a package fails until every list is updated.

## Dependency graph

The production `[dependencies]` edges between Crucible packages are:

```text
crucible-qemu-shmem         -> crucible-qemu-protocol
crucible-device             -> crucible-determinism, crucible-qemu-shmem
crucible-qemu-host          -> crucible-engine, crucible-device,
                               crucible-qemu-protocol, crucible-qemu-shmem
crucible-qemu-plugin        -> crucible-qemu-protocol, crucible-qemu-shmem
crucible-guest              -> crucible-qemu-protocol
crucible-qemu-debug-gateway -> crucible-qemu-protocol
crucible-engine             -> crucible-determinism, crucible-campaign,
                               crucible-store, crucible-device,
                               crucible-qemu-protocol,
                               crucible-qemu-shmem (optional, test-double)
crucible-campaign           -> crucible-store
crucible-session            -> crucible-engine, crucible-qemu-protocol
crucible-control-api        -> crucible-engine, crucible-qemu-protocol,
                               crucible-session
crucible-control-client     -> crucible-engine, crucible-qemu-protocol,
                               crucible-session, crucible-control-api
crucible-control-server     -> crucible-engine, crucible-qemu-protocol,
                               crucible-session, crucible-control-api,
                               crucible-control-client
crucible-daemon             -> crucible-device, crucible-control-client,
                               crucible-control-server, crucible-engine,
                               crucible-control-api, crucible-campaign,
                               crucible-store, crucible-qemu-protocol,
                               crucible-qemu-host, crucible-qemu-shmem,
                               crucible-store-s3, crucible-session
crucible-cli                -> crucible-control-client, crucible-control-server,
                               crucible-control-api, crucible-campaign,
                               crucible-daemon, crucible-session
crucible-store-s3           -> crucible-store
```

`crucible-determinism`, `crucible-qemu-protocol`, `crucible-store`, and
`crucible-test-support` have no Crucible production dependencies.

### Layer rules

`tests/crate_layer_graph.rs` (`checks.crucible.phase1.crateLayerGraph`) reads
each runtime package's `[dependencies]` table, resolving `package =` renames,
and rejects:

- an edge to a crate in a higher layer;
- a dependency cycle among Crucible packages;
- any runtime dependency on the test-only `crucible-test-support`;
- a direct dependency of an in-VM crate (`crucible-qemu-plugin`,
  `crucible-guest`) on anything other than an L1 crate.

The one sanctioned upward edge is `HOST_DRIVER_ENGINE_EDGE_EXCEPTIONS`:
`crucible-qemu-host` to `crucible-engine`. The engine declares the backend
traits it drives (`Backend` and `SimulationBackend` in
`crates/crucible/crucible-engine/src/backend.rs`) and names no QEMU, process,
or FFI type; the host-side QEMU driver implements those traits, so the
dependency points from the implementation to the interface. The exception
never applies to the in-VM crates, which share only the versioned
shared-memory and protocol contracts with the host. The plugin's only
Crucible dependencies are the two dual-licensed L1 protocol crates, which
keeps engine code out of the QEMU address space and out of the GPL-side
combined work.

### Control-plane and scheduler boundaries

`tests/control_plane_boundary.rs` (`checks.crucible.phase1.controlPlaneBoundary`)
keeps the CLI a thin client. In `[dependencies]` and target-specific
dependency tables, including workspace-inherited and renamed entries,
`crucible-cli` may depend only on the Crucible crates in
`CLI_ALLOWED_CRUCIBLE_DEPENDENCIES`: `crucible-control-api`,
`crucible-control-client`, `crucible-control-server`, `crucible-campaign`,
`crucible-daemon`, and `crucible-session`. A production dependency on
`crucible-engine` is always rejected. Test-only `[dev-dependencies]` are not
restricted, so CLI integration tests may use engine test helpers.

`tests/single_scheduler_boundary.rs` keeps one authoritative scheduler. The
engine's `scheduler` module defines `QuantumLoop`, `QuantumRequest`, and
`ScheduledEventKey`, and `crucible-session` must depend on the engine and
drive `QuantumLoop` through `SessionDriver`. No lower or peer crate
(`crucible-determinism`, the L1 and L2 crates, `crucible-store`,
`crucible-store-s3`, `crucible-campaign`, `crucible-test-support`, or
`crucible-cli`) may define `QuantumLoop`, expose `drive_quantum`, or call it in
non-test code; only the session, API lifecycle, and daemon execution
authorities drive the L3 boundary.

## Unsafe fence

The safe/unsafe boundary is drawn between crates, not between modules. A crate
either forbids `unsafe` entirely or is an enumerated unsafe-boundary crate.
This lets the engine be a clean safe island in its own crate rather than a
hopefully clean subtree of a crate that also maps shared memory.

| Fence | Crate-root attribute | Crates |
| --- | --- | --- |
| Safe | `#![forbid(unsafe_code)]` | `crucible-determinism`, `crucible-device`, `crucible-qemu-debug-gateway`, `crucible-engine`, `crucible-store`, `crucible-campaign`, `crucible-store-s3`, `crucible-session`, `crucible-control-client`, `crucible-control-server`, `crucible-control-api`, `crucible-daemon`, `crucible-cli` (`src/main.rs`), `crucible-test-support` |
| Unsafe boundary | `#![deny(unsafe_op_in_unsafe_fn)]` | `crucible-qemu-shmem`, `crucible-qemu-protocol`, `crucible-qemu-host`, `crucible-qemu-plugin`, `crucible-guest` |

Each unsafe-boundary crate needs `unsafe` for a specific reason:

| Crate | Why it needs `unsafe` | Safe surface (crate-root contract) |
| --- | --- | --- |
| `crucible-qemu-shmem` | `mmap` of the shared region, `#[repr(C)]` access across the boundary, lock-free SPSC atomics | Safe typed region accessors and safe SPSC push and pop wrappers that uphold alignment |
| `crucible-qemu-protocol` | Unix `sendmsg`/`recvmsg` with `SCM_RIGHTS` for setup descriptor handover; the frame codec itself is pure | Safe descriptor-handover wrappers that validate the fixed three-fd order and descriptor count |
| `crucible-qemu-host` | Process and descriptor boundaries for QEMU supervision and shared-memory mapping | A safe host-driver API that validates process and mapping invariants |
| `crucible-qemu-plugin` | QEMU's plugin C ABI: `extern "C"` entry points and raw QEMU pointers | Validate raw QEMU inputs and delegate to safe Rust shims |
| `crucible-guest` | The trapped doorbell instruction and direct shared-region access from inside the guest | Safe doorbell and marker accessors that uphold guest register and shared-region invariants |

`tests/crate_unsafe_fence.rs` (`checks.crucible.phase1.crateUnsafeFence`)
enforces:

- Each crate root carries exactly its declared fence attribute and not the
  other one. Only active inner attributes count; commented-out or
  string-embedded attributes are ignored.
- Each unsafe-boundary crate root documents its safe-wrapper contract under
  an `Unsafe boundary discipline:` paragraph with the phrases in the right
  column above.
- In a safe crate, any `unsafe` token is a finding. Test sources under
  `tests/` may use `unsafe` only with an adjacent `// SAFETY:` comment.
- In an unsafe-boundary crate, every `unsafe` block and `unsafe impl` has an
  adjacent `// SAFETY:` comment that states a non-empty invariant; every
  `unsafe fn`, `unsafe trait`, or `unsafe extern` function, and every public
  unsafe API, has a preceding `# Safety` doc section; and an `unsafe extern`
  block exposes no `pub` item.

A new unsafe boundary requires an explicit ownership review and a
matching change to the fence list and its compatibility checks. The engine and
control plane remain safe.

## Features

Cargo features are additive: no feature is mutually exclusive with another,
`default` always selects a working configuration, and every declared
combination compiles. The current feature declarations are:

| Crate | Feature | Enables |
| --- | --- | --- |
| `crucible-engine` | `default` | nothing |
| `crucible-engine` | `test-support` | test-only helpers |
| `crucible-engine` | `test-double` | `dep:crucible-qemu-shmem` and the `SimDouble` module |
| `crucible-qemu-host` | `default` | nothing |
| `crucible-qemu-host` | `test-support` | `crucible-engine/test-double` for live comparison examples |
| `crucible-device` | `default` | nothing; one uniform I/O model |
| `crucible-session` | `test-support`, `test-double` | `test-double` forwards to `crucible-engine/test-double` |
| `crucible-control-server` | `test-support` | `crucible-engine/test-support` |
| `crucible-daemon` | `test-support` | server, engine, and QEMU-host `test-support` |
| `crucible-cli` | `test-double` | `crucible-session/test-double` |
| `crucible-store` | `test-support`, `destructive-recovery-faults` | destructive storage-recovery fault injection for recovery tests |
| `crucible-campaign` | `test-support`, `destructive-recovery-faults` | forwards to `crucible-store` |
| `crucible-daemon`, `crucible-cli` | `destructive-recovery-faults` | forwards down to `crucible-store` |
| `crucible-cli` | `packaged-midpoint-flight` | packaged-flight test entry points |

`SimBackend`, the safe deterministic local backend, is always available. Only
the shared-memory `SimDouble` sits behind `test-double`, and no shipped crate
may enable it. `tests/feature_powerset.rs`
(`checks.crucible.phase1.crateFeaturePowerset`) checks:

- the exact feature tables of `crucible-engine`, `crucible-qemu-host`, and
  `crucible-device` shown above;
- that every feature case resolves (engine default, no-default,
  `test-support`, `test-double`, and both; QEMU-host production and
  `test-support`; device default and no-default);
- that no shipped package enables `test-double` on its `crucible-engine`
  production dependency;
- that `crucible-guest` is never a non-optional or default-activated dependency
  of a core package. The guest emitter is opt-in white-box tooling.

Engine gate targets that use the shared-memory double run with
`--features test-double`; see the target table in
[testing-and-gates.md](testing-and-gates.md).

## Artifact types

`tests/crate_artifact_types.rs` (`checks.crucible.phase1.crateArtifactTypes`)
fixes the build artifacts:

```toml
# crates/crucible/crucible-qemu-plugin/Cargo.toml: the only cdylib
[lib]
crate-type = ["cdylib"]

# crates/crucible/crucible-cli/Cargo.toml
[[bin]]
name = "crucible"
path = "src/main.rs"

# crates/crucible/crucible-store/Cargo.toml
[[bin]]
name = "crucible-fleet-store"
path = "src/bin/crucible-fleet-store.rs"

# crates/crucible/crucible-qemu-debug-gateway/Cargo.toml
[[bin]]
name = "crucible-debug-gateway"
path = "src/main.rs"

# crates/crucible/crucible-guest/Cargo.toml
[[bin]]
name = "crucible-guest"
path = "src/main.rs"
```

The plugin must declare exactly `["cdylib"]`; no other package may build a
`cdylib`; each binary package declares exactly its one named binary; every
other package is a library. The QEMU-loaded `cdylib` is built against the AOS
QEMU package's plugin headers as part of the hermetic package build described
in [packaging.md](packaging.md).

## Determinism and QEMU boundaries

The harness lint partitions the crates by how much host nondeterminism they may
touch. The lists live in
`crates/crucible/crucible-test-support/tests/support/harness_lint/common.rs`.

- **Reduction path** (`REDUCTION_PATH_PACKAGES`): `crucible-determinism`,
  `crucible-test-support`, `crucible-engine`, `crucible-qemu-protocol`,
  `crucible-device`, and `crucible-session`. Their sources may contain no host
  wall clock or monotonic time, no thread, global, or OS RNG, no
  `HashMap`/`HashSet` or default random hasher, and no unordered `select!`.
- **Host-nondeterminism boundary** (`NONDETERMINISTIC_BOUNDARY_PACKAGES`):
  `crucible-daemon`, `crucible-cli`, `crucible-qemu-debug-gateway`,
  `crucible-qemu-host`, and `crucible-store-s3`. They may read host time or
  schedule background work in supervision and diagnostics code, but such
  values must not be publicly exported or routed into run state (`State`,
  `Configuration`, `Schedule`, `Decision`, `QuantumRequest`, the backend
  traits, `reduce`, `step`, `instantiate`). Of these, only `crucible-cli`,
  `crucible-daemon`, and `crucible-qemu-host` may depend on `crucible-engine`
  directly. A value that must affect a run goes through the seeded decision
  source in `crucible-determinism`.
- **Everything else** is scanned with the reduction-path rules and reported as
  "not a host-nondeterminism boundary"; existing findings are capped in
  `tests/crucible/harness-lint-baseline.txt` and may only shrink.

The in-VM crates are on the determinism-critical path too, but their
determinism is intra-VM hermeticity, proven by the execution-fingerprint gates
rather than by host-side import rules.

QEMU-specific code is likewise confined. `tests/engineering_hygiene.rs`
treats `crucible-qemu-debug-gateway`, `crucible-daemon`, `crucible-qemu-host`,
and `crucible-qemu-plugin` as the QEMU boundary packages: other crates may not
depend on them or use QEMU-specific tokens (`qemu`, `QMP`, `savevm`, `loadvm`,
`crucible_qemu`, and case variants) outside comments and strings. The two
public protocol crates are exempt by name because they define permissive
process protocols, not a QEMU implementation. Existing debt is listed as
`qemu-token` and `qemu-manifest` rows in
`tests/crucible/engineering-hygiene-baseline.txt`.

## Standalone dependencies

Crucible ships standalone and carries the small content-addressed store surface
it needs in `crucible-store` instead of sharing a substrate with another AOS
engine. `tests/standalone_dependencies.rs`
(`checks.crucible.phase1.standaloneDependencies`) rejects any Crucible
dependency, direct, workspace-inherited, renamed with `package =`, or
target-specific, on a crate named `ratchet` or `aos-nix` or prefixed `ratchet-`
or `aos-nix-`. Keeping the seam inside `crucible-store` means a later shared
substrate is a contained refactor rather than a prerequisite.

## Workspace settings

The Crucible packages are members of the single AOS virtual workspace, which
pins one toolchain and one dependency-version set. Packages use edition 2024.
The workspace denies these clippy lints for every member:

```toml
[workspace.lints.clippy]
all = "deny"
disallowed_methods = "deny"
disallowed_types = "deny"
expect_used = "deny"
float_arithmetic = "deny"
unwrap_used = "deny"
```

The disallowed method and type lists live in `crates/clippy.toml`; see
[engineering-standards.md](engineering-standards.md) for the full banned set
and how exceptions are annotated.
