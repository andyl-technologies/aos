# Troubleshooting Crucible

Start with the process exit code. It classifies the failure before the detailed
message or event log does.

## Exit `4`: backend discovery or configuration

### QEMU or plugin was not found

Build and invoke the complete package closure from the repository root in
`nix develop` or its direnv environment:

```sh
aos-dev build package crucible
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
the complete `crucible` package rather than mixing outputs from different
commits or copying only the shared object. The CLI validates the QEMU build ID,
atomic-patch hash, shared-memory ABI, and plugin ABI before launch.

### Kernel or root image is missing

The packaged binary has compile-time asset paths. A binary built directly with
Cargo may not. Either run the packaged binary or set:

```text
CRUCIBLE_KERNEL
CRUCIBLE_ROOT_IMAGE
CRUCIBLE_RUN_STATE_ROOT
```

`CRUCIBLE_RUN_STATE_ROOT` must name a writable directory that persists across
CLI restarts. Use `CRUCIBLE_INITRD` only when the guest requires one.

### Campaign deployment or host-resource admission failed

Local QEMU runs require a provisioned deployment selected by the global
`--campaign-deployment PATH`, `CRUCIBLE_CAMPAIGN_DEPLOYMENT`, or
`/etc/crucible/packaged-executor.toml`. The file must meet the exact ownership,
mode, and version requirements in [campaign setup](campaigns.md#start-the-single-host-owner).
The same setup describes the dedicated cgroup-v2 root, ext4 project quotas,
reserved project IDs, and child credentials. Package installation does not
create them, and an arbitrary temporary directory is not an alternative.

### Execution shape or capability is refused

Unattended local QEMU runs reject `--save-on fail` and `--save-on always`.
Use the default `never` and the dedicated `save` command for durable handles.
Check the [current execution refusals](support.md#current-execution-refusals)
for due inputs, native preemption commands, and linked advances without a safe
positive tick. These are capability failures; raising a timeout cannot fix them.

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
  resume /path/to/savepoint.crucible-savepoint
```

Bare checkpoint hashes are not portable savepoints and fail normal admission.

### Triage input lacks discovery evidence

`triage` accepts the signed findings ledger emitted by `search` or `fuzz`, not
a directory of reproduction artifacts and not an individual `.crucible`
artifact. Rerun the campaign with `--findings-out <path>` when automation needs
a predictable ledger path, then pass that path to `triage`.

## Exit `3`: identity, oracle, crash, or server failure

### Reproduction build identity mismatch

Replay requires the engine, artifact ABI, QEMU build, atomic patch, shared-memory
ABI, guest-host protocol, RPC ABI, and plugin ABI recorded by the producer.
Rebuild or recover the exact package revision that created the artifact.

Production replay accepts only the v4 live-QEMU artifact contract. Any other
contract fails closed before execution; the current CLI has no compatibility
decoder.

Do not bypass this check: replay under a different deterministic substrate is a
different experiment.

### Replay-oracle violation

A materialized checkpoint and reduction from its ancestor produced different
state. Preserve the artifact, store, trace, and complete build closure. This is
a Crucible correctness failure, not an expected scenario outcome.

### Daemon or backend crashed

Run the same scenario locally with the packaged backend. If local execution
works but the daemon route fails, confirm the daemon was started with
`--production-qemu`. Its default quiescent lifecycle is for API testing.

## Exit `2`: timeout

The run reached a modeled virtual-time or scheduler-quantum bound. A timeout is
not a property violation. Decide whether the budget is the intended assertion
or only a safety bound, then adjust the user-configurable budget or terminal
condition within the [lifecycle limits](running.md#terminal-conditions-and-budgets).
A host step deadline or campaign watchdog is an operational failure, not a
modeled timeout finding; inspect its backend diagnostic instead.

Check duration syntax: only positive integral `ticks`, `ns`, `us`, `ms`, and `s`
values are accepted.

## Exit `1`: property failure or divergence

### Property failure

Retain the emitted `.crucible` artifact and replay it before changing the test:

```sh
./result/bin/crucible replay <artifact>
```

Then save immediately before the failure boundary if an alternate
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
