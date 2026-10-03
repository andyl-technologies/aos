# Running Crucible in CI

Use the packaged Crucible closure in CI. It contains the CLI, patched QEMU,
plugin, kernel, and fixture image as one matched set.

## Build and qualify the runner

Build once at the start of the job and run the packaged gates before executing
project scenarios:

```sh
aos-dev --release build package crucible
./result/bin/crucible --quiet selftest
```

Production builds run the QEMU-backed gates by default. A failure here means
the runner is not qualified; do not continue with scenario results from that
job.

Run these commands from the repository root in `nix develop` or its direnv
environment. `--release` selects ordinary derivations and requests no shared
compiler-cache mounts. Daemon-wide static mounts can remain visible; use a
separate builder if qualification requires a cache-free sandbox.
Provision the [guarded host resources](campaigns.md#start-the-single-host-owner)
before scenario execution, and set `CRUCIBLE_CAMPAIGN_DEPLOYMENT` to the
owner-only deployment file and `CRUCIBLE_RUN_STATE_ROOT` to a durable writable
directory. The deployment must admit the example's 100,000 execution quanta.

## Run a scenario

Keep the scenario and its guest inputs under source control or produce them as
fixed build outputs. Give every CI run an explicit seed, store, trace path, and
budget:

```sh
mkdir -p .ci/crucible/store .ci/crucible/artifacts

set +e
./result/bin/crucible \
  --seed 0x8a54f31d \
  --store .ci/crucible/store \
  --artifact-dir .ci/crucible/artifacts \
  --trace .ci/crucible/events.jsonl \
  --format jsonl \
  --quiet \
  run scenarios/checkout.scn \
  --until virtual-time \
  --max-virtual-time 1s \
  --max-quanta 100000
status=$?
set -e

exit "$status"
```

The explicit `--format` makes the output independent of whether the CI runner
allocates a terminal. Failure artifacts are distinct from savepoint handles;
unattended local QEMU runs use the default `--save-on never`. Virtual-time and
quantum limits bound modeled execution; host completion also has its own
operational deadlines. See [timeout semantics](running.md#terminal-conditions-and-budgets).

Archive these paths on failure:

- `.ci/crucible/events.jsonl`;
- `.ci/crucible/artifacts/`; and
- `.ci/crucible/store/`, unless the job uses a durable content-addressed store.

Reproduction artifacts carry their authenticated closure, subject to the
recorded backend/build requirements. Savepoint handles and canonical scenario
inputs can still reference the store. Preserve it when retaining those inputs.

## Interpret exit status

Crucible uses stable process classes so CI does not need to parse prose:

| Status | Meaning | CI treatment |
| ---: | --- | --- |
| 0 | The command completed successfully. | Pass. |
| 1 | Property failure, divergence, replay mismatch, counterexample, or triage failure. | Fail and retain the reproduction. |
| 2 | A configured virtual-time or quantum bound expired. | Fail or classify as a scenario timeout. |
| 3 | Crash, daemon failure, replay-oracle failure, or build-identity mismatch. | Fail and preserve diagnostics. |
| 4 | The backend failed. | Fail and inspect runner/QEMU diagnostics. |
| 5 | Invalid scenario, artifact, store object, or local I/O input. | Fail and repair or restore the input. |
| 64 | Command-line usage error. | Fail and fix the invocation. |

See [Running Crucible](running.md#exit-codes) for command-specific detail.

## Add a determinism gate

After a scenario passes its ordinary run, compare independent reductions:

```sh
./result/bin/crucible \
  --seed 0x8a54f31d \
  --store .ci/crucible/store \
  --format jsonl \
  --quiet \
  verify scenarios/checkout.scn \
  --runs 2 \
  --bisect
```

Two runs are a useful pull-request gate. Increase `--runs` for scheduled jobs
when the extra backend time is justified. `--bisect` prints the first causal
divergence if fingerprints or canonical logs differ. The report keeps evidence
coordinates distinct: `first_virtual_time` comes from a canonical-log event,
while `first_instruction` comes from a fingerprint sample. A coordinate is
`unknown` when that evidence stream does not localize the mismatch. Each
coordinate has its own adjacent node field; do not pair an instruction count
with `first_virtual_time_node`.

## Recheck a reported failure

Download the archived artifact and store, then replay against the original
canonical log:

```sh
./result/bin/crucible \
  --store .ci/crucible/store \
  --format jsonl \
  replay .ci/crucible/artifacts/failure.toml \
  --check .ci/crucible/events.jsonl
```

Use the actual artifact filename emitted by the failed run. A replay exit of
`0` confirms that a fresh packaged-QEMU run reached the recorded terminal
configuration with identical event and fingerprint streams, and that the
retained canonical log matched. Exit `1` means live replay or the explicit log
check diverged; exit `5` means an artifact, store object, or local input was
invalid or unavailable.

## Parallel jobs

Shard by scenario and seed, not by sharing a writable store directory. Give
each concurrent process its own `--store`, `--artifact-dir`, and `--trace`
paths. A useful matrix is:

```text
scenario × fixed regression seeds × supported host architecture
```

Keep regression seeds stable in pull-request jobs. Run broader seed campaigns
on a schedule and promote any finding to the fixed regression set only after
its artifact replays.

## Keep secrets out of scenarios

Scenario files, traces, guest consoles, and reproduction artifacts are CI
outputs, not secret stores. Use synthetic credentials inside test guests. Do
not inject production tokens, private signing keys, or customer data into a
Crucible run.
