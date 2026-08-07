---
name: crucible-debugger
description: Reproduce and diagnose deterministic Crucible scenario failures with the Crucible CLI, retained artifacts, live daemon sessions, reverse operations, and mediated GDB. Use when a Crucible scenario fails, crashes, times out, diverges during replay, or needs guest-state inspection without changing the canonical run.
---

# Crucible Debugger

Use the CLI as an evidence-gathering tool. Preserve the seed and canonical run,
state a diagnosis from observed evidence, and distinguish implemented live
debugging from preview-only surfaces.

## Prepare the CLI

From the AOS repository, build the packaged suite when practical:

```sh
nix build .#crucible
```

For an incremental development build, use the repository dev shell and then
run the binary directly:

```sh
nix develop -c cargo build --manifest-path crates/Cargo.toml --bin crucible
crates/target/debug/crucible --help
```

Do not use `cargo run`. Run hands-on acceptance separately from Nix checks so a
failure remains available for inspection.

## Reproduce before debugging

Run with the reported seed, a finite budget, and failure artifact retention:

```sh
crucible \
  --seed 0xdeb6 \
  --format table \
  --artifact-dir /tmp/crucible-debugger-artifacts \
  run scenario.toml \
  --until property \
  --save-on fail \
  --max-quanta 100
```

Record the exit status, terminal outcome, assertion IDs, frontier, quanta,
artifact path, and seed. Do not infer the cause solely from the scenario's
failure message.

`--save-on` controls the terminal savepoint policy. A failed run still retains
its reproduction artifact when `--save-on never` is selected; do not interpret
that artifact as an unexpected savepoint.

For the repository exercise, use
`assets/inverted-crash-expectation.scenario.toml`. Its source generator is
`crates/crucible/examples/crucible-debugger-failing-scenario.rs`; edit the
generator and regenerate the canonical TOML rather than hand-editing component
IDs.

## Inspect retained evidence

Confirm that local artifact debugging fails honestly until the runtime executor
is available:

```sh
crucible debug /tmp/crucible-debugger-artifacts/repro-*.crucible --at-failure
crucible debug /tmp/crucible-debugger-artifacts/repro-*.crucible \
  --at-failure reverse-step assertion
```

Artifact-targeted commands decode the artifact fields needed to identify the
failure coordinate, but they do not provide a local time-travel session. They
therefore exit `4` with `no debug operation was executed`; a zero exit or a
planned-only success is a bug.
Use `replay --check`, `verify --bisect`, explicit savepoints, or a live daemon
session when the retained artifact is insufficient.

Compare these sources before diagnosing:

- assertion predicate and message in the canonical scenario;
- terminal outcome and assertion violation in CLI output;
- event history and failure coordinate in the retained artifact;
- live node state, registers, and threads when attached to a daemon session.

## Use live debugger operations

Start `serve --production-qemu` on an isolated loopback or authenticated mTLS
endpoint, create a paused inline-scenario session, and retain its complete
`id:epoch:seed` reference. Then use CLI debugger verbs against the session:

```sh
crucible --daemon http://127.0.0.1:9000 --trusted-unauthenticated-daemon \
  debug --session ID:EPOCH:SEED --node suspect reverse-step assertion

crucible --daemon http://127.0.0.1:9000 --trusted-unauthenticated-daemon \
  debug --session ID:EPOCH:SEED --node suspect \
  --gdb-listen 127.0.0.1:0 attach-gdb
```

Connect the suite's matching `gdb` to the printed loopback address. Use GDB to
read registers, threads, and memory. GDB `step` advances one deterministic
scheduler quantum; it is not raw QEMU single-instruction stepping.

Keep canonical inspection read-only. Pass `--allow-mutate fork-debug` only when
the investigation truly needs a non-canonical branch, and label all resulting
evidence non-canonical.

## Report limitations as findings

Do not work around a missing or misleading CLI affordance silently. Report the
command, expected behavior, actual behavior, exit status, and whether evidence
was canonical.

The shipped fixture currently does not activate `crucible-guest agent` at fork
time. The `exec`, `pty`, and `ssh` transports exist, but are preview-only and
are expected to fail closed until fork-time activation is completed. Do not
claim guest-shell validation from transport admission alone.

Finish with a concise diagnosis, the evidence supporting it, the first faulty
scenario or implementation assumption, and any debugger usability bugs found.
