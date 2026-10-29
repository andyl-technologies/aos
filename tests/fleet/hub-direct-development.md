# Fast Direct development checks

Run the small local checks before the full fleet qualification:

```sh
aos-dev test hub-direct
```

This compiles the current checkout incrementally, runs the Worker unit tests and
Native Direct unit tests, then exercises actual workerd guard journals across
three process lifetimes and a Native/Worker/provider integration scenario. The
connected scenario uses fresh SQLite state, signed provider requests, a common
three-request provider limit, an 8 MiB source, and cold terminal replay. It does
not boot VMs or build the packaged CLI, registry publication corpus, or browser
console.

On the development host, warm `stress` runner invocations took 42–43 seconds.
The signed scenario itself completed in 39 seconds while VM prerequisites were
building. The full local suite completed in 47.1 seconds with 489 focused Rust
unit tests plus guard restart and connected provider checks. The separate
authority bootstrap suite passed 27 tests. These are local development measurements, not
release performance requirements. Nix evaluation, shell entry and cold compiler
work add to the command's total wall time.

Use a narrower loop while editing:

```sh
aos-dev test hub-direct unit
aos-dev test hub-direct runtime
aos-dev test hub-direct paired
aos-dev test hub-direct queue
aos-dev test hub-direct stress
```

`runtime` exercises the one-binding integration baseline with the shared provider
capacity policy enabled. `paired` selects the independent two-binding scenario,
including its separate source Read profile. A failure in `paired` remains a
product/integration failure; the baseline does not qualify that scenario.

`queue` stages 24 real signed multipart uploads, then drains the actual Miniflare
verification queue through the production immutable integrity and narinfo readers.
`stress` uses 32 queued objects (eight content and 24 metadata), 64 independent
foreground upload owners, four foreground rounds, and 50 ms controlled provider
latency. It checks positive first-delivery receipts, requires every queue wait to
stay below eight seconds and every enqueue-to-finish interval below ten seconds,
and requires metadata admission during bulk verification. Actual object and
provider concurrency remain bounded by three, with at most two bulk objects.
The foreground fanout reproduced the fleet's roughly 1.8-second capacity waits
without booting VMs or transferring gigabytes. Both use the matching Miniflare
runtime shipped with Wrangler; the older standalone Miniflare is incompatible
with current workerd's queue protocol.

The initial metadata-only stress scenario failed against the previous provider scheduler: its maximum
queue wait was 24.6 seconds. With eligible request classes taking turns, the same
scenario passed with a 5.7-second maximum wait. It verified all 32 queued objects
while 64 foreground owners completed 256 additional uploads. Those foreground
uploads are separate from the 32 verified queue objects. These measurements
describe this controlled reproduction, not the full fleet workload.

The Worker tests also exercise shared object admission across both queue classes.
A delivery refused before acquiring capacity emits a retry without inventing a
verification finish. Admitted deliveries retain matched start and finish events
before their actual acknowledgement or retry.

The mixed queue scenario also covers shared object admission. A full object pool
keeps deliveries waiting locally and rotates eligible bulk and metadata work.
It preserves FIFO within each class and the reserved metadata slot. Ordinary
contention must not consume the queue's finite delivery attempts: the local
runtime drops a message after its third failed delivery. Acceptance and protected
material are checked again after waiting, before verification begins.

The small mixed workload reproduced that failure against the retained earlier
Wasm: only 30 of 32 originals verified before the 60-second drain deadline. With
fair object waiting, all 32 verified in 7.3 seconds, with first-delivery receipts
for every original and metadata admission during bulk work. The longest measured
enqueue-to-finish interval was 6.8 seconds. The 256 foreground uploads also
completed. This remains a controlled development regression, not full fleet
qualification.

The first build may need to compile dependencies. Later runs reuse
`CARGO_TARGET_DIR`, the agent worktree's Cargo target when available, or
`$XDG_CACHE_HOME/aos-dev/hub-direct-target` (with `~/.cache` as the default cache
root). The Wasm development build uses optimization level 1, no debug information,
and incremental compilation instead of release LTO. The generated module wiring
matches `pkgs/tools/aos-hub-worker-dist.nix`; both runtimes execute current code.
The Direct shell clears inherited compiler and linker flags from an enclosing
development shell before using its own AOS toolchain and library paths.

Each test phase has a 180-second deadline. Worker compilation has a separate
600-second cold-build deadline. Use `--timeout SECONDS` to change test deadlines
up to 600 seconds. Every phase reports elapsed time. Failure stops the loop,
terminates its process group (including workerd), and retains private output;
successful runs remove scratch state. `--keep` retains successful logs too.
The runtime scenario reports provider header and capacity-wait timing aggregates
without printing private request or response contents. Its optional Fetch timing
wrapper returns each original response without consuming or replacing its body.

These checks cover local invariants and controlled integration. They do not
establish provider qualification, cross-VM behavior, bulk concurrency, publication
recovery, or acceptance of a production runtime. Keep the full Direct and Proxy
fleet scenarios as final qualification; a local pass does not replace them.

The separate `_hub-direct-development.nix` fixture reduces the actual signed
publication workload to three 16 MiB content objects and 64 added metadata
objects. Its APR inventory includes the real helper package and dependencies;
the unrelated CLI and Native packages are excluded from this development release.
It retains the APR-authored release, ordinary publisher CLI, independent
Native/Worker/database/provider VMs, shared three-request provider policy, real
verification queues, and the Visibility enqueue that starts publisher B. Both
publishers must reach `ready`, and their content hashes and metadata catalogue
must match their sources. Publication has a 180-second deadline.

This fixture still performs ordinary authority setup and prequalification before
the bounded publication phase. The outer setup-and-test deadline is 30 minutes;
that is not a claim that setup takes three minutes. It skips the full scenario's
sparse interruption and subsequent fault windows. Its results cannot qualify
those cases or the original stress workload.

Construct it with explicitly selected immutable runtime inputs so fixture edits
reuse the existing service packages and VM images:

```nix
let
  runtime = builtins.storePath "/nix/store/<selected-immutable-runtime-source>";
  aos = import runtime {};
  spec = import ./_hub-direct-development.nix {
    inherit (aos) lib pkgs;
    mkSystem = import (runtime + "/tests/fleet/_hub-fixture-system.nix") {
      inherit (aos) mkSystem;
    };
    runtimeSource = runtime;
    runtimeSourceIdentity = {
      sourceCommit = "<selected-commit>";
      sourceTree = "<selected-tree>";
    };
  };
  harness = import (runtime + "/lib/testing/fleet.nix") {
    inherit (aos) lib pkgs;
  };
in harness.mkFleetTest spec
```

The normal independent review checkpoints remain required. Each run uses fresh
VM state. `external-direct-flow/development-summary.json` records numeric queue
wait, active-delivery, provider-header, body and capacity-wait distributions,
including failed publication runs. The same summary is printed in the controller
log. Private publisher and service logs are written alongside the summary in the
build directory; use `--keep-failed` to preserve that directory after a failure.
Successful Nix builds remove this scratch directory, so retain the controller log
when comparing successful runs. The helper's boundary and queue-accounting checks
run with the AOS Python:

```sh
python3 -B tests/fleet/_hub-direct-development-tests.py
```

The independent `shared-runtime-controls` checkpoint uses the source-built
`aos-fleet-controls` fixture in `tests/fleet/fleet-controls`. Build it before
starting the fleet:

```sh
AOS_FLEET_CONTROL_CODEC_REVISION="$reviewed_commit" \
  nix develop --file cargo-shell.nix -c cargo build \
  --manifest-path tests/fleet/fleet-controls/Cargo.toml --locked
```

Set `reviewed_commit` to the shared codec revision independently matched to the
installed Native and Worker sources. The fixture prepares ingress and issuer
requests and verifies actual signed issuer replies through existing shared Rust
APIs. Retain its source, fixture lock, executable and actual AOS library
resolution for the checkpoint's provenance document. Its revision identifies
the shared codecs; the helper source has its own digest. The helper grants no
provider authority or runtime acceptance. Keep the selected executable private;
the fixture rejects a helper accessible to other users.

The full controller export also accepts `nativeBodyObservationTools`. Pass the
independently built observation package for the selected runtime when running
the later queue fault windows. Those windows require its Native body codec;
the smaller development publication stops before those checks.
