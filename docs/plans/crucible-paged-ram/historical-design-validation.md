# Historical design-completion validation record

The design audit and format validation on 2026-10-05 used RFC revision
`991bf1e3549d4d6838711afb0bf6e62b736f3468`. Repository checks ran against the
same runtime, package, and test sources, unchanged from the source baseline
in the overview. Subsequent documentation edits add this record and clarify
qualification wording; they change no normative requirements or format
fixtures. This record supplies evidence about the document, its fixtures,
and the executed repository checks; it does not qualify an implementation
of this proposal. The `gate:ram-*` gates remain future work.

Every Nix invocation disabled remote builders with `--option builders ''`.
Checks were invoked through the AOS development shell and repository CLI;
production check derivations used `aos-dev --no-cache`. Local builds may reuse
existing store outputs, but no test execution was offloaded to another host.

| Validation | Outcome | Evidence and limit |
|---|---|---|
| Document integrity | PASS | All 234 requirement definitions are unique and contiguous within their families; local requirement references, document links, tagged fences, and JSON syntax are valid. |
| RAM format fixtures | PASS | A freshly compiled official BLAKE3 1.8.5 portable C implementation agreed with independent reconstruction of 15 named digests, every tree level and supplied preimage, and all three scoped roots. Domain, endianness, length, padding, and scope controls were also checked. |
| Nix formatting | PASS | All 2,046 Nix files passed Alejandra. |
| Rust formatting | FAIL | `aos-dev fmt all --check` reported differences in unchanged baseline Rust files. The check did not modify them. |
| System evaluation and structure | PASS | The `eval` check completed locally, including its Linux 7.2.3 and ZFS dependencies. |
| Packaged Rust test targets | PASS | `rust.aos-test-targets` compiled all application unit and integration test targets. This compilation check does not execute their tests. |
| Packaged license boundary | PASS | All 18 boundary tests passed. Its controller prerequisite also passed Clippy, doctests, and 5,560 executed tests across 266 binaries, with 75 explicitly skipped tests. |
| All-features Rust workspace | FAIL | Compilation completed and the `--no-fail-fast` run finished with seven failed test targets, listed below. This run does not establish an all-green workspace. |
| Full repository aggregate | BLOCKED | `all checks` failed during evaluation on missing Samba resource classifications, before it could schedule the full check inventory. |
| Crucible phase 1 aggregate | BLOCKED | Evaluation rejected the baseline `packaged-midpoint-flight` feature declaration without a consuming `cfg`. |
| Shared-memory ABI check | FAIL | Eight Rust cases passed; the unchanged generated C fixture then failed to compile against renamed or removed instruction-count fields. This is not a passing ABI gate. |
| VM boot basics | FAIL | The guest booted and passed OS-release, hostname, and running-system checks, then failed an unchanged assertion requiring `6.18` in `uname -r`; the repository builds Linux 7.2.3. Later assertions did not execute. |
| Packaged live SQL dialects | FAIL | Local VM fixtures started PostgreSQL 18.6 and MariaDB 12.3.3. PostgreSQL and SQLite contracts passed; the MariaDB contract failed on an unchanged GC query with unknown column `cache_gc_generations.cutoff_at`. |

The aggregate failures are explicit missing coverage, not waivers. The package
platform-support check requires classifications for
`networking/_samba-cross/aarch64-linux.answers` and
`networking/_samba-cross/heimdal-build-tools.nix`. The ABI fixture still names
`icount_shift` and `preemption_*_icount` fields that its current public headers
do not expose. These sources, the feature declaration, and the VM assertion
were not changed to obtain a passing result for this documentation change.

The workspace command used a separate worktree-owned Cargo target directory,
denoted by `RFC_CARGO_TARGET_DIR` below:

```bash
nix develop --accept-flake-config --option builders '' -c \
  env CARGO_TARGET_DIR="$RFC_CARGO_TARGET_DIR" \
  cargo test --manifest-path crates/Cargo.toml --workspace --all-targets \
  --all-features --no-fail-fast -j 16
```

Its failed targets were:

- `-p aos --test apr_cache_cli`
- `-p aos-hub --test dialect`
- `-p aos-hub-core --lib`
- `-p aos-package --lib`
- `-p crucible-api --lib`
- `-p crucible-cli --test campaign_store_process`
- `-p crucible-cli --test gate_campaign_store_composition`

The workspace dialect failures reported missing live database URLs. The separate
packaged live-SQL result above uses actual fixtures and therefore supplies
different evidence. Three failures from the parallel workspace run passed when
rerun individually using the same compiled executables with `--test-threads=1`:
the Hub concurrent baseline installation test, its expired inventory range-owner
test, and Crucible's host-continuation clone-cost test. The latter originally
reported 88,352 KiB private memory for 64 clones. Isolated reruns do not erase
the original failures or establish the other failed targets passed. No runtime
or test sources were edited to address these failures in this RFC change.

The packaged check commands were:

```bash
nix develop --accept-flake-config --option builders '' -c \
  aos-dev fmt all --check

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache all checks \
  --no-out-link --keep-going --option builders '' --show-trace

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check eval \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check rust.aos-test-targets \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check crucible.phase1 \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check crucible.phase2.shmemAbiConformance \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check crucible.phase1.gates.licenseBoundary \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check vm.boot-basics \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check integration.aos-hub-dialect-tests-live-dialects \
  --no-out-link --keep-going --option builders ''
```

The earlier format review additionally established agreement with the official
Rust reference, 210 primitive checks, agreement across 35 selected-mode input
lengths, and nine RAM mutation controls. The completion run above freshly
recompiled the C implementation and reconstructed the RAM fixtures; it did not
repeat every earlier primitive/reference experiment. Neither set of format
results supplies live page-fault, eviction, fork, or transfer evidence.
