# Deferred execution and generations

This page covers what happens after evaluation: graph admission, the handler
process protocol, effect identity and lifetimes, package generations, recovery,
retention, and container bootstrap. See [evaluation](evaluation.md) for how the
graph is produced.

## Graph admission

Nix lowers the selected fixed point to `aos.activation.graph`, carried inside an
`aos.package.transaction` document. `aos_module_format::graph` checks identities,
revision hashes, native option type projections, references, composition
exports, ordering, and bound handlers. Arbitrary Nix predicates without a
portable validator cannot cross this boundary. Missing handlers, incompatible
outputs, cycles, invalid exports, and malformed identities are rejected before
execution.

The original JSON is retained for stable hashing and replay. Declared sets are
normalized again after deferred results are substituted, because two references
may return the same value and returned values may sort differently from their
symbolic identities. Ordered lists, such as command sequences, keep their order.

A terminal handler is a retained program artifact with a main executable. A
composed handler expands into typed children and result exports; only terminal
nodes launch processes. Input references are resolved from checked producer
results in dependency order.

## Handler process protocol

`aos_deployment::handler::ProcessAdapter` launches the handler with one
argument, `apply`, `remove`, or `observe`, and writes a serialized
`aos_activation::activation::Invocation` to stdin. That type is the source of
truth for the invocation shape, including the effect, resolved inputs, and
previous state.

Successful `apply` prints the declared result object on stdout, for example
`{"message":"hello"}`. Successful `remove` prints `{}`. `observe` prints one of:

```json
{"status":"current","outputs":{"message":"hello"}}
{"status":"absent"}
{"status":"retry-safe"}
{"status":"indeterminate"}
```

Stdout is protocol data; diagnostics belong on stderr. The transport
(`aos_deployment::process`) bounds stdin, stdout, stderr, duration, and
cancellation, and a failed process never yields a successful result. The
current transport uses Linux process facilities.

## Identity, revision, and lifetime

Logical effect identity is the installation scope, declaring package, ability,
operation, and instance name; composed children also include their parent.
Package versions, store paths, and handler artifacts do not change logical
identity. When several packages extend shared domain configuration, the domain
manager derives the resulting effects and owns their lifecycle.

Revisions derive from semantic inputs and the selected implementation.
Description and documentation edits do not change a revision, and authors do not
maintain revision counters. `after` orders execution; a dependency's result
belongs in `input` when its changes should change the consumer's revision.
Changed inputs or implementations receive the previous state for reconciliation.

The effect journal distinguishes three lifetimes:

- `transaction`: removed after dependent operations finish;
- `instance`: retained across generations and removed when configuration
  disappears;
- `persistent`: retained until explicitly retired, including after package
  removal.

`aos.activation.retire` lists the exact retained identities to release. The
canonical deployment carries this decision; callers do not pass a second
retirement list to `Transactions::apply`. Configured or unknown identities are
rejected before preparation, and completed retirements remain valid in later
generations.

Filesystem claims record the effect's exact path and entry kind rather than
device and inode numbers, which change across image layers and container
instances. Observation checks requested metadata, copied content, and symlink
targets. An existing unclaimed destination is rejected before an old path is
released, and removal never follows a tree link into its source.

## Generations and recovery

`aos_deployment::transaction::Transactions` coordinates a generation journal
with the effect journal. It prepares the exact document before dispatch and
commits once the selected `ExecutionPolicy` finishes:

- `Complete` requires every selected effect to finish.
- `Installation` commits checked installation results together with the exact
  startup effects, and their dependents, that remain pending. It is not
  evidence that services have started.

The effect runtime journals intent and completion, checks results, and observes
uncertain operations before retrying. An `indeterminate` observation stops
progress instead of assuming success or repeating an unsafe action; failed
reloads, cancellation, and process loss are never converted into success. The
runtime never assumes that arbitrary external mutations can be undone.

The most recent caller transaction receipt records its policy, results, and
deferred work, closing the crash window between effect completion and
generation commit without repeating one-shot work. Recovery resumes interrupted
work under its original policy before accepting another generation. It first
checks completed resource prerequisites through durable restoration intents,
preserving the pending invocation and its original results.

Rollback applies a retained desired document as a new transaction; it does not
rewind the execution journal. `prune` journals removal of an older generation's
roots and retries interrupted cleanup; the current generation cannot be pruned.
Journals use checksummed framing, exclusive locking, and configured size limits.
They stop at capacity, and pruning does not compact them; automatic journal
compaction is not implemented.

`aos_deployment::transaction::inspect` reads the same journals under a shared
lock through the same decoder and replay state machine. It cannot create or
repair journals. `ActivationInspection::retained_effects` exposes completed
invocations and checked results without promoting pending work; these records
are excluded from ordinary inspection JSON and exported only after the paired
journals, committed publication, artifact admission, and effect roots validate.

## Retention

`aos_deployment::retention::NixStore` roots generations and handlers through an
explicitly supplied `nix-store` executable. Its `ArtifactAdmission` trait binds
those roots to the package manager's authenticated resolution or retained
receipts and requires already-realized artifacts. Registry authentication and
profile-link publication stay with the calling consumer; the generation journal
is the authoritative committed pointer.

Old handler artifacts remain rooted until their update, teardown, or recovery no
longer needs them, and persistent effects keep independent handler roots.
Artifact release is journaled separately.

Image staging preserves physical store custody as well as GC roots. Under the
generation read lock, the package layer supplies authenticated system-profile
inputs and orphan handlers; the OS storage backend preserves their closures,
both image implementations, and the module libraries before replacing an
immutable root. Existing copies must match NAR identity and Unix modes; new
copies are verified and durably published before the first root-slot write.

Boot may adopt the original provisioning receipt into the first host
generation. The image's retained policy decides whether that receipt is
required, and later generations preserve its provenance. Boot preparation hands
the retained export to the selected identity backend, which validates the
complete receipt-owned account projection before publishing database changes and
preserves foreign rows.

## Container bootstrap

Container preparation and startup use the same committed profiles and effect
journals. Preparation runs the `Installation` policy; startup runs `Complete`
only after validating the selected init command and the PID 1 lifetime.
Consecutive installations may supersede startup work that never executed, and a
second image-build installation never starts services from the first.

`initSystem.install` (`pkgs/system/_init-system/module.nix`) identifies the
retained init executable and arguments; machine boot and container startup
supply its handlers. The systemd package declares the installation-phase
`systemdBootstrap.prepare` operation in
`pkgs/system/_systemd-abilities/container-bootstrap.nix`. Its service and
resource-group inputs reuse the corresponding `serviceManagement` input
submodules. `bootstrap-provider.py` renders units with the ordinary canonical
renderers and imports the unit tree into the local Nix store as a recursive
content-addressed artifact. Its results identify the owned resource, store path,
and NAR digest, without contacting a running manager.

The bootstrap handler durably records the predicted store-root intent before
importing, and records preparation custody, including the exact recipient
identities, before changing unit aliases. Ordinary service and resource-group
handlers later adopt the prepared seed through their own custody records.
Replaced or foreign definitions fail closed, and bootstrap retirement waits until
no recipient custody remains.

Service-owned storage and standalone filesystem effects must not manage the same
directories. On retirement the systemd handler stops the owned service and
durably transfers any private persistent directory backing to its public path,
checking exact aliases and entry identities first.

## Execution observation

The controller exposes durable boundaries to an optional observer
(`aos_activation::activation::Boundary`): `IntentDurable`,
`DispatchStarted`, `DispatchReturned`, `OutcomeDurable`, `ObservationStarted`,
and `ObservationReturned`. Production execution without an observer needs no
Crucible closure; `aos-activation-crucible` and
`modules/profiles/ability-crucible.nix` provide the optional instrumentation.

`DispatchStarted` precedes the adapter call and does not prove that the handler
ran. When observation is configured as required, observer failure stops progress.
A controlled interruption recovers through the same production journal and
handler observation path; test code never rewrites completion records or turns
an indeterminate outcome into success.
