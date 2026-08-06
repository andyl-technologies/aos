# Troubleshooting Crucible

Start with the process exit code. It classifies the failure before the detailed
message or event log does.

## Exit `4`: backend discovery or configuration

### QEMU or plugin was not found

Build and invoke the complete package closure:

```sh
nix build .#pkg-crucible
./result/bin/crucible selftest
```

If you intentionally use separate artifacts, supply both members of the pair:

```sh
./result/bin/crucible \
  --qemu /nix/store/.../bin/qemu-system-x86_64 \
  --plugin /nix/store/.../lib/libcrucible_qemu_plugin.so \
  selftest
```

Do not add an arbitrary host QEMU to `PATH`; Crucible does not consult it.

### Build marker or ABI mismatch

QEMU and the plugin must come from the same Crucible package set. Rebuild
`pkg-crucible` rather than mixing outputs from different commits or copying only
the shared object. The CLI validates the QEMU build ID, patch-series hash,
shared-memory ABI, and plugin ABI before launch.

### Kernel or root image is missing

The packaged binary has compile-time asset paths. A binary built directly with
Cargo may not. Either run the packaged binary or set:

```text
CRUCIBLE_KERNEL
CRUCIBLE_ROOT_IMAGE
```

Use `CRUCIBLE_INITRD` only when the guest requires one.

## Exit `5`: scenario, artifact, store, or I/O input

### Scenario does not exist

Scenario input must be an existing regular file, a recognized built-in, or a
`blake3:<hash>` in the selected store. Check the spelling and `--store` path.

### Canonical TOML failed validation

Canonical scenario TOML includes derived content IDs. Generate it through the
Rust scenario model and avoid hand-editing IDs. If content changes, regenerate
the document so world, plan, properties, and scenario identities agree.

### Store object cannot be resolved

Use the same store root as the producing command:

```sh
./result/bin/crucible \
  --store /path/to/original/store \
  resume blake3:<checkpoint>
```

For a portable handoff, prefer the exported savepoint handle or failure
artifact over a bare checkpoint hash.

## Exit `3`: identity, oracle, crash, or server failure

### Reproduction build identity mismatch

Replay requires the engine, artifact ABI, QEMU build, patch series, shared-memory
ABI, guest-host protocol, RPC ABI, and plugin ABI recorded by the producer.
Rebuild or recover the exact package revision that created the artifact.

Production replay accepts the v3 live-QEMU artifact contract only. A v2 or
model-only artifact must be reproduced with the older matching Crucible build;
the current CLI will not silently reinterpret it.

Do not bypass this check: replay under a different deterministic substrate is a
different experiment.

### Replay-oracle violation

A materialized checkpoint and reduction from its ancestor produced different
state. Preserve the artifact, store, trace, and complete build closure. This is
a Crucible correctness failure, not an expected scenario outcome.

### Daemon or backend crashed

Run the same scenario locally with the packaged backend. If local execution
works but the daemon route fails, remember that the current daemon uses the
quiescent development lifecycle rather than production QEMU.

## Exit `2`: timeout

The run reached `--max-virtual-time`, `--max-quanta`, or a fixed local-QEMU
lifecycle bound. A timeout is not a property violation. Decide whether the
budget is the intended assertion or only a safety bound, then increase the
user-configurable budget or select a different terminal condition. Raising
`--max-quanta` does not raise the fixed 40-billion-instruction per-node ceiling.

Check duration syntax: only positive integral `ticks`, `ns`, `us`, `ms`, and `s`
values are accepted.

## Exit `1`: property failure or divergence

### Property failure

Retain the emitted `.crucible` artifact and replay it before changing the test:

```sh
./result/bin/crucible replay <artifact>
```

Then save or fork immediately before the failure boundary if an alternate
schedule needs investigation.

If replay reports a terminal, event-stream, or fingerprint-stream divergence,
retain both the artifact and complete packaged QEMU
closure. Those errors mean the fresh guest execution did not reproduce the
recording; they are not ordinary assertion failures.

An interactive run can finish normally, but Crucible will reject live-QEMU
failure-artifact capture until interactive commands can be recorded and replayed
at exact scheduler coordinates. Re-run non-interactively to produce a portable
artifact.

### Verify divergence

Repeat with a fixed seed and bisection enabled:

```sh
./result/bin/crucible \
  --seed <recorded-seed> \
  verify scenario.toml \
  --runs 2 \
  --bisect
```

Preserve both side artifacts. Do not start a search or fuzz campaign until
ordinary repeated reductions agree.

### Replay `--check` mismatch

`--check` compares canonical log bytes, not a table rendering or arbitrary
stdout capture. Generate and retain the original with `--format jsonl --trace`.

## Exit `64`: command-line usage

Use subcommand help for exact current syntax:

```sh
./result/bin/crucible <command> --help
```

Common mistakes include:

- using `--until virtual-time` without `--max-virtual-time`;
- combining a fork seed with `--override`;
- passing both positional `FAMILY` and `--family` to `fuzz`;
- selecting multiple debugger coordinates; and
- using `--format markdown` for an event-log-producing command.

## Collecting a useful report

For a reproducible issue report, retain:

- the exact Git revision and `result/nix-support/crucible-build-info`;
- the complete command and exit code;
- the fixed seed;
- JSONL output and `--trace` file;
- the failure artifact or savepoint handle;
- the associated `.crucible/store` when store references are involved; and
- whether the command used local QEMU or `--daemon`.

Do not include host wall-clock timing as evidence of canonical divergence. Use
the first differing event, instruction count, fingerprint, or state hash.
