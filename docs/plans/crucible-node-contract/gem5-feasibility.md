# gem5 exact-continuation feasibility and source foundation

This report records the G0 source audit and implementation prerequisites for
T-CN-15 through T-CN-19. It accompanies the implementation plan; the public
contract remains [RFC-0025](../../rfcs/0025-crucible-node-contract/README.md).

## Audited identity and admission status

The audited upstream revision is
`f5c5a6e390f55dd5984977815bf9d0bd05da6945`, whose `src/base/version.cc`
declares version `25.1.0.1`. The source archive has SHA-256 SRI
`sha256-WPQcs29vcMMtHDHYEZORRYaaQDny3yT54OTY+AOQMgU=`. File links below
refer to that revision, not a moving release branch.

The source-build foundation is [gem5.nix](../../../pkgs/emulation/gem5.nix).
It builds upstream's `ALL` configuration and keeps Python configuration,
protobuf tracing, HDF5 statistics, Capstone disassembly and tcmalloc available.
Supporting source recipes supply SCons, Capstone, HDF5 and libaec; existing AOS
packages supply the compiler, Python, protobuf, zlib and gperftools. The pinned
embedded pybind11 uses AOS Python 3.12 instead of the newer Python 3.14 C API.
No pip download, host library, nixpkgs package or remote builder is required.

The package is initially declared for native Linux builds on the builder's CPU;
cross compilation and cross-host package checks are not advertised. A tracked
[compiler-target query patch](../../../pkgs/emulation/gem5-patches/compiler-target-query.patch)
uses `-dumpmachine` instead of a verbose compiler invocation, because the AOS
compiler wrapper injects link flags. The patch changes build discovery only;
its digest is part of the installed source manifest. It does not add native
control or complete-state serialization.

The [build environment patch](../../../pkgs/emulation/gem5-patches/reproducible-build-environment.patch)
retains `SOURCE_DATE_EPOCH` and `PYTHONHASHSEED` through SCons's subprocess
environment filter. The recipe fixes both for compiler date strings and Python
generators. Two independent artifact builds still need to be compared before
reproducible binary output is certified. Runtime statistics may contain wall
timestamps; those must not become modeled time or semantic state commitments.

The installed `share/gem5/source-manifest.json` explicitly records that the
binary does not implement CNP/1 and has neither qualified exact capture nor
qualified live branching. Successful source compilation and the upstream
learning example establish package functionality only. They do not establish
complete-state preservation, full-system Linux boot, device parity, exact
stops or repeatability.

The local source build completed with all selected upstream ISA/protocol models,
including the x86 and Arm generators, and passed the upstream learning example.
The event-only process-image witness passed source exit followed by two fresh
reconstructions. The owned-file custody witness passed two concurrent,
divergent reconstructions with separate writable files. Real x86_64 and
AArch64 O3/classic-cache/DDR3 witnesses also passed two concurrent, private-output
reconstructions after source exit and removal of the source's owned output
root. These are mechanism results; the qualified CPU/device list remains empty.

The [native gem5 license inventory](../../../pkgs/emulation/gem5-patches/LICENSES.md)
and [DMTCP patch inventory](../../../pkgs/tools/_dmtcp/LICENSES.md) identify the
modified upstream files and retained licenses. Successful test results do not
authorize an incompatible native license combination or waive applicable
source-distribution obligations.

Production admission for the RFC-0025 gem5 exact profile must remain disabled.
The source audit demonstrates concrete missing state, rather than an absence
of paperwork. A failed or unsupported checkpoint must be refused before world
activation; there is no architectural-only fallback for an exact request.

### Implemented native boundary foundation

The [pre-event boundary patch](../../../pkgs/emulation/gem5-patches/nondraining-event-boundary.patch)
adds `simulateUntilBoundary(exclusive_tick, max_events)` in the native loop and
Python API. It services the permitted event prefix and leaves the next native
event queued. It neither inserts a limit event nor moves an idle queue's native
clock to the requested horizon. An event budget can stop between events having
the same tick and priority without reordering the remaining in-bin chain.

The initial primitive rejects parallel event queues, asynchronous host inputs,
mixing with stock synthetic limit events, and resuming a drained owner. It
shares ordinary startup with the stock Python interface; it does not invoke
`simulate(0)` as an initialization shortcut. Initialization and authorized
execution may perform startup work; capture itself does not call this wrapper.
Logical frontier conversion, native event ordinals, incoming delivery ordering,
early output custody and CNP/1 owner control remain separate implementation work.
The patch is not a declaration of the complete `deterministic_exact` profile.

### Pipeline initialization regression

The real O3 witness exposed stale pipeline-slot fields under AOS's source-built
GCC 16 optimizer. Upstream `TimeBuffer` zeroes storage before placement default
construction; that does not initialize scalar members during the new payload's
lifetime. A focused fixture using the actual `TimeBuffer` and `RefCountingPtr`
headers preserved the previous size, sequence and flag after slot recycling.
The same fixture passed with lifetime dead-store analysis constrained.

The [value-initialization patch](../../../pkgs/emulation/gem5-patches/time-buffer-value-initialization.patch)
constructs new and recycled payloads with `T()`, placing the required scalar
initialization within the object lifetime. The
[native regression](../../../pkgs/emulation/_gem5/time-buffer-check.cc)
fails against the unpatched header and passes against the patched header at
the package's optimized build settings. This repairs pipeline initialization;
it does not supply pipeline capture diagnostics or checkpoint qualification.

## Capture blockers in the pinned source

| State domain | Observed upstream behavior | Required nondraining implementation |
| --- | --- | --- |
| Checkpoint entry point | `m5.checkpoint()` calls `drain()` and `memWriteback()` before `serializeAll()` | A separate exact capture entry point that pauses host execution without executing modeled work |
| O3 execution | `CPU::serializeThread()` delegates to the thread serializer, which exports `ThreadContext` | Preserve speculative instructions, register maps/files, ROB, queues, stage/time buffers, translations, functional-unit reservations and all references |
| Classic caches | `BaseCache::serialize()` saves a dirty-state warning flag; cache data is not serialized and dirty restore is fatal | Preserve tags/data/coherence/replacement state, MSHRs, targets, write buffers, pending responses and retries |
| Ruby coherence | `RubySystem::serialize()` requires a recorder created by `memWriteback()` | Preserve controller state, transient entries, message buffers, network/router state, credits, transactions and protocol events directly |
| DRAM controller | Read/write/response queues and rank/bank refresh/power timing exist outside a complete arbitrary-boundary serializer | Preserve queue order, packet references, scheduler direction, bank state, timing constraints, command history and pending events |
| DMA | `DmaReadFifo::serialize()` asserts `pendingRequests.empty()` | Preserve outstanding requests, completion ownership, buffer state and remaining transport work |
| Event queue | Individual events serialize time, priority and flags; equal-key events use a linked in-bin stack | Preserve queue membership and exact native tie order, asynchronous insertion state and typed callback ownership |
| Random generators | `Random` instances contain `std::mt19937_64` engines and a live instance registry | Preserve every engine's current state and owning object; reseeding is insufficient |
| Virtio queues | Common queue serialization saves address and last-available index | Audit descriptor/request lifetimes, completion state, transport register state and derived caches for each offered device |
| 9p proxy | A used proxy warns serialization/restoration is likely to lose state; host server/socket state is external | Replace or extend with a capturable semantic service plus preserved sessions, handles and in-flight requests |

These are direct source observations. The table is an initial inventory, not a
claim that every future-affecting member has been enumerated. The complete
inventory must include the realized object graph and every configured CPU,
device, cache, memory controller, clock, transport and workload object.

Sources: [checkpoint entry point][checkpoint], [O3 CPU][o3-cpu],
[O3 thread context][o3-thread], [O3 rename stage][o3-rename],
[classic cache serializer][classic-cache], [Ruby checkpoint path][ruby],
[memory controller][mem-ctrl], [DRAM ranks and banks][dram],
[DMA serializer][dma], [event queue implementation][eventq],
[random engines][random], [virtio common queues][virtio], and
[9p proxy serializer][ninep].

### Why existing alternatives do not discharge the contract

A stock drained checkpoint moves the model toward a different state before
capture. A cache flush changes future hits, coherence work and memory timing.
Replaying instructions to warm caches does not reconstruct the original
pipeline, predictor, queue or event state. An architectural-state export loses
the very microstate for which a detailed simulator was selected. These are
different continuation semantics even when Linux later prints the same line.

Same-host process COW can preserve private modeled heap bytes, including
in-flight state, but does not produce a durable artifact restorable after the
origin dies. A generic process image also contains pointers, interpreter state,
file descriptors and host resources that cannot be exposed as CNP shared-memory
objects or assumed valid in a fresh process. Live branching and durable capture
therefore require separate formats, reconstruction paths and certificates.

## Full-process durable capture path

A second representation can preserve the complete private modeled object graph
without requiring each upstream SimObject to serialize its speculative state:
capture the stopped native process image. The source-built
[DMTCP package](../../../pkgs/tools/dmtcp.nix) pins release `4.2.0`, revision
`f8009ce7b4ad211311ca2f72a929b975e4aa1155`, with source SHA-256 SRI
`sha256-BDQQVm/XwJ8h4OxIXPculIFyJinqh3ZQFCt1BeDX8tI=`. The package preserves
the public generated version header and replaces conventional shell/loader
paths with AOS-built tools. Its application-initiated mechanism check captures
a nonempty linked equal-time event queue, private memory and current PRNG state,
allows the original application to exit, then reconstructs the image twice in
fresh processes and compares complete fixture state and ordered future traces.
This establishes the tool mechanism for that fixture, not gem5 exactness.

DMTCP is LGPL-3.0-or-later and must retain its notices and applicable source
obligations. Its public application header has a permissive license. This path
is evaluated for the gem5 native process. Preloading it into GPL-2.0-only QEMU
requires an independent compatibility determination; the gem5 work does not
authorize that combination. Sources: [pinned DMTCP release][dmtcp-release],
[public API and plugin lifecycle][dmtcp-api], and [license][dmtcp-license].

### Capture and restore lifecycle

1. Realize and admit a complete configuration and resource inventory. The first
   process-image profile uses one native event queue; all actual host threads
   still require capture, suspension and restoration. Disable automatic periodic
   checkpoints. A provider-owned capture request is permitted only at its
   stopped pre-event boundary, after semantic endpoint/control custody has been
   established. No call to upstream checkpoint, drain, fork or cache writeback
   occurs in this path. Reserve and bind the checkpoint signal explicitly:
   gem5 uses `SIGUSR2` for dump/reset statistics, which conflicts with DMTCP's
   default. The Linux mechanism fixture uses signal 40; a production provider
   must inventory its complete signal usage and compatibility constraints.
2. Bind all durable dependencies before requesting the process image: immutable
   executable/library/interpreter closure, firmware/kernel/disk objects, private
   modeled RAM, external semantic owners and any native auxiliary process.
   The DMTCP coordinator is an operational capture service, not simulation-time
   authority. Its state cannot replace the Crucible world manifest.
3. Invoke the application-initiated checkpoint while the model is stopped. Its
   return distinguishes capture continuation from reconstruction. The API only
   guarantees completion for the calling process; a multi-process owner needs
   a generation barrier and successful images from every required participant
   before publication. The initial single-process witness rejects multiple
   image files instead of silently ignoring extra custodians.
4. Authenticate and publish the full image/resource closure with implementation,
   schema, architecture, CPU/cache/coherence/memory/device configuration and
   host-format constraints. Native process images contain process-private
   addresses internally. They remain opaque implementation-bound bytes;
   public manifests use verified content objects and checked references, never
   native addresses, live PIDs or borrowed descriptors as artifact references.
5. Before reconstruction, verify the complete closure and compatibility key,
   including native host architecture, kernel/ABI requirements, executable and
   loaded-library identities, DMTCP implementation, patches and configuration.
   Missing or changed components fail before modeled execution. Exact virtual
   addresses restored by the native image format are not a claim of portability.
6. Restart with a fresh operational incarnation while the model remains stopped.
   Reconstruct private resource bindings and reconnect CNP control before any
   execution grant. Compare observational microstate/event commitments at the
   cut. The source may already be dead; no origin pointer, mapping or socket may
   remain necessary. Release the owner only after the world restore transaction
   admits every participant.

The [gem5 mechanism check](../../../pkgs/emulation/gem5-continuation-check.nix)
uses this route with genuinely pending native Python events. It compares an
uninterrupted prefix, bounded pause-and-continue, capture-and-continue and two
fresh reconstructions after source exit. At the cut, fifteen events remain,
including equal-tick/equal-priority siblings; the fixture's state commitment
includes current PRNG, memory, scheduled-event membership, trace prefix and the
next native boundary. This check must pass before the mechanism is used, but
its empty qualified CPU/device list prevents mistaking it for a detailed CPU,
cache, DRAM, DMA or full-system qualification certificate.

The separate [x86 O3 witness](../../../pkgs/emulation/gem5-o3-continuation-check.nix)
and [AArch64 O3 witness](../../../pkgs/emulation/gem5-arm-o3-continuation-check.nix)
use source-built freestanding guest workloads, an O3 CPU, two L1 caches, L2,
and DDR3 timing memory. AOS LLVM/LLD builds the AArch64 guest; both guests
implement the same memory/branch algorithm and compare their result against
independently executed native x86 code. The checks run the identical installed
ALL gem5 binary on this machine.

Each witness pauses after a fixed native event prefix, captures without calling
any drained checkpoint path, lets the original exit, removes its owned output
root, and reconstructs two processes concurrently with independent output
files and path bindings. It compares ordered native future event traces,
guest-computed memory results, execution-event counts and final native ticks
with capture-and-continue and the same uncaptured workload. These checks expand
the process-image witness beyond Python events; their pass status must be
reported separately for each architecture. They still lack complete
observational pipeline/cache/controller commitments, deliberate state-domain
omission tests, full-system DMA/device coverage and authenticated CNP owner
integration. Their results explicitly do not qualify the exact profile or
native live branching.

### External custody is a hard admission boundary

| Native resource | Pinned DMTCP behavior or risk | Required owner treatment |
| --- | --- | --- |
| Control connection to the Crucible host | A socket whose peer is outside the captured group is restored as a dead socket | Snapshot semantic command/output custody separately; bind a fresh authenticated operational connection before activation |
| Writable disk/output files | File restoration can reopen original paths and may overwrite saved files when configured | Immutable backing objects plus new private overlays/output paths per incarnation; never reopen a parent/sibling writable resource as child custody |
| Writable `MAP_SHARED` backstore | Shared regions have a separate file/shared-resource restoration path; they are not automatically independent private model heap | Reject uncontrolled shared resources or reconstruct branch-private bindings and all qualified fault registrations before release |
| Virtual RAM pager and `userfaultfd` registration | A restored FD number does not reconstruct mappings, fault registrations, pager progress or backing-object leases | Admit private/eager RAM initially; qualify an explicit pager reconstruction path before allowing lazy restored RAM, keeping population service available under capture barriers |
| 9p helper or another native subprocess | Single-process checkpoint completion does not prove complete peer custody | Capture and authenticate the entire group, or replace the helper with a semantic node whose exact state participates in the world cut |
| Host listeners, TAP, USB or other external I/O | Native process images cannot reconstruct uncaptured physical peer state | Use capability-scoped mediated endpoints; refuse exact admission when peer state/output custody is unavailable |
| Native libraries and kernel-backed resources | Restore behavior depends on the actual native format and host interfaces | Declare and test exact host constraints, resource reconstruction and unsupported-resource refusal |

These constraints follow from the source, not merely tool limitations described
in general documentation: [external socket handling][dmtcp-sockets],
[file reopen/overwrite paths][dmtcp-files], and
[shared-mapping inventory][dmtcp-shared]. Userspace checkpointing does not by
itself establish privilege independence for every configured resource. The
small local fixture requires neither CRIU nor a privileged kernel checkpoint
operation; full gem5 configurations remain subject to their actual FD, mapping,
signal, thread and memory-fault requirements.

### Implemented owned-file reconstruction mechanism

The [native custody helper](../../../pkgs/emulation/gem5-process-custody.nix)
implements DMTCP's file-copy and already-open-file reconstruction hooks for an
explicit owned resource root. Files in that root are captured with their open
descriptor state and restored into a distinct private incarnation root. Future
opens use one matching `DMTCP_PATH_MAPPING` binding. Missing, nested, identical
or inconsistent bindings are refused; the provider must additionally verify
canonical paths, private directory custody, immutable backing identities and
the complete descriptor/resource inventory before admitting a configuration.
This helper does not infer ownership for arbitrary files outside the root.

Both reconstruction routes are required. Built-in path translation covers future
opens, while `FileConnection::refreshPath()` consults the separate
`dmtcp_get_new_file_path` hook before reopening an existing descriptor. Also,
file reconstruction runs before the process-info plugin increments its restart
counter. The helper recognizes the reserved restart-environment FD instead of
using that late counter to distinguish restoration from source continuation.

The concurrent mechanism witness snapshots an already-open writable file and
private memory, allows the source to exit, then reconstructs two processes from
the same artifact with different inputs and private resource roots. It checks
saved file content/offset, divergent writes, future-open paths and preservation
of origin/sibling files. This is evidence for owned-file reconstruction; it is
not a certificate for an arbitrary filesystem semantic node, native live fork,
shared RAM, network sockets, physical devices or the full gem5 owner closure.
The artifact closure must include DMTCP's saved-file directory alongside its
process-image file; keeping only the `.dmtcp` image would lose these resources.

This witness exposed a pinned upstream environment-parser defect. The original
`dmtcp_get_restart_env` loop bounds a buffer using `sizeof(pointer)`, and matches
name prefixes rather than complete environment names. The
[bounded environment patch](../../../pkgs/tools/_dmtcp/restart-environment-bounds.patch)
reads the NUL-delimited environment using its actual byte count, permits embedded
newlines in values, checks string bounds and matches `name=` exactly. The helper
regression includes complete-name and multiline values, and an origin-alias
restore that must fail before file mutation. This patch and helper identity
belong to the native implementation compatibility key.

Before restoring a captured open file, the helper requires a canonical
incarnation path and an existing regular destination with a single link.
Symlink and hard-link aliases are refused before saved bytes can be overwritten.
The native custody test also reconstructs a third process after deleting the
source's owned files and directory, verifying that the saved-file artifact is
sufficient for this resource set. These checks do not prove that arbitrary
shared mappings, mount aliases, subprocesses or external devices are capturable.

The witness also checks the actual checkpoint signal. gem5 owns `SIGUSR2` for
statistics, so the process-image mechanism selects signal 40 and verifies that
the tool installed that signal before capturing. Pinned DMTCP parsed a valid
signal using `strtol` without clearing a previous `errno`, silently falling
back to `SIGUSR2`. The
[signal-parser patch](../../../pkgs/tools/_dmtcp/checkpoint-signal-parse.patch)
validates the complete number while preserving the caller's previous error.
The native regression starts with a nonzero `errno` and verifies both the
selected signal and unchanged caller error. Passing a command-line option
alone would not establish signal custody.

### Exactness evidence remains model-specific

Preserving native heap bytes is a promising way to retain O3 instructions,
cache contents, coherence transients, DRAM timing, packets, callbacks and current
RNG engines together. It is not sufficient to hash the image bytes and call the
result a semantic microstate commitment. Native images also contain allocator,
interpreter, operational and wall-time state; byte integrity proves artifact
integrity, while complete model diagnostics and ordered continuation tests
prove preservation of future-affecting simulation state.

The remaining detailed qualification must construct nonempty witnesses for
every promised CPU/cache/coherence/controller/device domain, read their state
without advancing the model, compare capture/restore controls, and deliberately
alter or omit each domain to show that the checker detects loss. A successful
console boot and the event-only process-image fixture do not discharge those
requirements. Resource-isolated live branching is separately unqualified;
durable reconstruction of a private heap is not evidence that two active
children have independent file/shared-memory/endpoint custody.

## x86_64, AArch64 and device parity

Upstream includes both x86 and Arm ISA builds and detailed CPU implementations.
ISA availability alone does not qualify a machine. Pin a realized configuration
for each architecture: CPU class and parameters, ISA feature set, clock domains,
memory controller, complete cache/coherence topology, interrupt controllers,
firmware/boot protocol, device models and semantic endpoint bindings.

The x86 [PC platform][pc] includes its native interrupt/timer/serial platform,
while Arm [RealView platforms][realview] offer GIC, PL011, timers and platform
devices. These are not declarations of a QEMU `virt` or PC device equivalent.
Guest-visible register layout, interrupt routing, firmware discovery and Linux
driver requirements must be tested for the selected platform.

The pinned `src/dev/virtio/` directory includes block, console, RNG and 9p
devices with PCI or Arm MMIO transport. It does not contain a virtio-net device.
Native Ethernet models such as e1000 do not establish virtio-net parity. Required
parity needs a correctly modeled controller or an explicitly admitted alternative
controller with the requested guest-driver and semantic behavior. It cannot be
reported as supported merely because an Ethernet endpoint exists.

For each requested device, qualification must cover discovery, ordinary I/O,
reset, hot interruption, errors, pending transactions at capture, fresh restore,
branch isolation and the supported features of its semantic node. Device parity
is a separate P5 gate; it does not repair incomplete CPU/memory capture.

## Native owner and durable graph design

Implement the following patch sequence in source owned by the gem5 process.
The Apache host uses only the versioned public process contract; native objects
and pointers stay within their originating process.

1. Add a native execution owner and CNP/1 adapter. Realize logical nodes while
   assigning their shared event queue and continuation to one exclusive owner.
   Configure clocks and conversion ratios explicitly, using checked arithmetic
   for coordinator time. Close external host inputs behind semantic adapters.
2. Add nondraining stop boundaries in the native event loop. Stop before the
   next disallowed native event or externally visible interaction; do not inject
   an exit event that displaces an existing equal-time event. Record native tick,
   priority and in-bin ordinal. Preserve outputs that stop execution early and
   requests awaiting the coordinator. Capture must leave the next event intact.
3. Introduce typed full-state visitors and stable graph identities. Each admitted
   stateful object declares a versioned type and complete state schema. Packets,
   requests, dynamic instructions and scheduled callback targets use checked
   object IDs, not native pointers. Unknown object types fail inventory closure.
4. Implement two-pass restoration: allocate admitted object identities without
   scheduling modeled work, then restore fields/references and queue ordering.
   Validate every reference, callback kind, topology edge, clock conversion,
   backing object, pending operation and ownership relationship before activation.
   Preserve cycles and shared references; never duplicate a single request into
   independently owned requests during deserialization.
5. Add serializers incrementally for O3 stages and predictors, classic caches,
   Ruby controllers/network, DRAM controller/interfaces, interrupt/timer/device
   state and every admitted transport. Record full random-engine state. Keep
   modeled dirty cache values distinct from backing RAM bytes: no writeback to
   normalize the artifact.
6. Publish immutable artifacts only after the entire owner closure is available
   and authenticated. Bind implementation/source identity, complete configuration,
   state schema and continuation semantics. Native state must be available after
   origin death; neither a RAM Merkle root nor a live child substitutes for it.

Generic event callbacks require particular care. `EventFunctionWrapper` may
carry a closure with captured pointers and private data. Recording its address
does not define a portable callback representation. Each admitted event must
resolve to a typed target/action plus captured modeled data, or the state is
unsupported. Capturing only `(tick, priority)` also fails because native equal-key
order is observable.

State digests must be independent of allocator addresses and operational pager
placement. They cover all future-affecting fields and canonical references.
Do not exclude queues, replacement metadata, RNG state or timers as
"performance-only": those change detailed-model future execution.

## Live fork, threads and external resources

The upstream [fork entry point][fork] requires disabled listeners, calls
`drain()`, terminates helper event-queue threads and then invokes `os.fork()`.
The [simulation loop][sim-loop] explicitly owns parallel event-queue worker
threads. Removing `drain()` without a replacement barrier is not a safe or exact
branch implementation.

The [RAM backing implementation][ram] uses `MAP_ANON | MAP_PRIVATE` by default,
but uses `MAP_SHARED` when shared backstore is configured. A child retaining a
shared writable backstore cannot claim parent/sibling RAM isolation. A live
branch profile must reject that configuration or construct isolated backing
before activation, without altering modeled RAM contents.

The fork registry must inventory every host worker and library thread, not only
the event queue count. One event queue does not prove a single-threaded process.
Audit Python/interpreter locks, allocators, output/statistics streams, sockets,
poll registrations, native listeners, disk descriptors and 9p subprocesses.
Listeners, output paths and coordinator connections need fresh child incarnations;
writable disk overlays must be private. Sharing immutable page objects is
allowed only with validated lifetime leases.

A parked control thread cannot hold a lock needed by RAM population or child
reconstruction. Pager service must operate while capture/fork barriers remain
held. Fork must re-establish resource ownership, control channels and fault
registrations before the child is released. Child failure cannot release the
parent's backing lease or publish partial world state.

## Required local evidence and exit conditions

Static audit and source compilation complete only the source-foundation portion
of G0. The dynamic nondraining tests below remain required before T-CN-15 can
be marked complete. The pre-event primitive and process-image mechanism do not
yet constitute a full-state qualified native owner.

For each admitted x86_64 and AArch64 detailed configuration, construct witnesses
with genuinely nonempty speculative pipeline, predictor history, dirty caches,
MSHR targets, DRAM queues/refresh, DMA, device retries and equal-key events.
Use three controls from the same admitted root: uninterrupted execution,
capture-and-continue, and capture followed by fresh-process restore. Kill the
origin before the third resumes. Compare full-state digests at the cut and
ordered modeled event/output traces afterward, not just guest console output.

Add negative tests that intentionally omit or alter each state domain; the
checker must detect loss. Corrupt references, unknown callbacks, unsupported
schemas, missing backing objects and configuration/source mismatches must fail
before execution. Capture must not retire instructions, advance tick/ordinal,
complete transactions, flush caches or drain the owner.

Separately qualify identical COW branches against the uninterrupted control,
then divergent branches against parent/sibling isolation. Exercise concurrent
threads, cold RAM faults under barriers, writable disks, listener reconstruction,
allocation pressure and child reconstruction failure. Durable restore success
does not imply live-branch safety, or vice versa.

All qualification runs use this machine and explicitly disable remote builders:

```text
aos-dev --release build package gem5 --no-out-link --option builders '' --cores 8
```

Package-build results and native continuation results must be reported separately.
Raw build logs and future traces remain local; the repository contains source,
small meaningful witnesses and concise conclusions. There is no performance
comparison with QEMU-SIM until equivalent workloads and declared fidelity
differences have been established.

[checkpoint]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/python/m5/simulate.py#L401
[fork]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/python/m5/simulate.py#L520
[o3-cpu]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/cpu/o3/cpu.cc#L717
[o3-thread]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/cpu/o3/thread_state.cc#L57
[o3-rename]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/cpu/o3/rename.hh
[classic-cache]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/mem/cache/base.cc#L2057
[ruby]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/mem/ruby/system/RubySystem.cc#L333
[mem-ctrl]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/mem/mem_ctrl.hh
[dram]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/mem/dram_interface.hh
[dma]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/dev/dma_device.cc#L463
[eventq]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/sim/eventq.cc#L138
[random]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/base/random.hh
[virtio]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/dev/virtio/base.cc#L242
[ninep]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/dev/virtio/fs9p.cc#L230
[pc]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/dev/x86/Pc.py
[realview]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/dev/arm/RealView.py
[sim-loop]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/sim/simulate.cc#L103
[ram]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/mem/physical.cc#L215
[dmtcp-release]: https://github.com/dmtcp/dmtcp/releases/tag/v4.2.0
[dmtcp-api]: https://github.com/dmtcp/dmtcp/blob/f8009ce7b4ad211311ca2f72a929b975e4aa1155/include/dmtcp.h
[dmtcp-license]: https://github.com/dmtcp/dmtcp/blob/f8009ce7b4ad211311ca2f72a929b975e4aa1155/COPYING.LESSER
[dmtcp-sockets]: https://github.com/dmtcp/dmtcp/blob/f8009ce7b4ad211311ca2f72a929b975e4aa1155/src/plugin/ipc/socket/socketconnection.cpp#L496
[dmtcp-files]: https://github.com/dmtcp/dmtcp/blob/f8009ce7b4ad211311ca2f72a929b975e4aa1155/src/plugin/ipc/file/fileconnection.cpp#L463
[dmtcp-shared]: https://github.com/dmtcp/dmtcp/blob/f8009ce7b4ad211311ca2f72a929b975e4aa1155/src/plugin/ipc/file/fileconnlist.cpp#L385
