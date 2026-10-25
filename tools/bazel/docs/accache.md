# Accache Rust execution profiles

The standalone accache qualification uses separate release and editor execution
profiles. Its Cargo release builds compile procedural macros at optimization 0,
with assertions and overflow checks disabled. The workspace's `strip = true`
also reaches those tools. The Cargo editor oracle explicitly supplies its
optimization-3 target flags globally, so editor macros receive those flags too.
First-party target compilation keeps its existing optimization-3 settings.

```text
nix-build tools/bazel/tests/accache.nix -A execution-profiles --no-out-link
nix-build tools/bazel/tests/accache.nix -A all --no-out-link
```

The [profile report](../tests/evidence/accache-execution-profiles.json) retains
four native Cargo macro compilation requests and the authenticated Bazel
compiler inputs for both macros and both first-party targets. All eight checked
Bazel compiler actions execute in Linux sandboxes without cache hits. The check
compares optimization, debug information, assertion/overflow settings, and
stripping. Compiler capability queries are excluded from compilation records;
duplicate or missing actual macro compilations fail the check.

Cargo traces retain requested arguments. The independent native Cargo profile
probe exercises default overflow behavior when Cargo omits the compiler flag.
These observations do not establish complete compiler, executable-chain,
native ABI, or linker equivalence.

The [full profile qualification](../tests/evidence/accache-profile-qualification.json)
passes with these settings. It retains 114 passing unit cases, 44 upstream
feature identities, the empty frontend doctest inventory, lint/format checks,
and installed runtime parity. Both editor models report the same 253 raw
diagnostic rows at 161 distinct locations/types; their aggregate inference
statistics still differ. The cache integration covers 524 fixture families,
924 revisions, and 534 compiler commands. The five recorded Bazel test,
developer, format, production, and editor executions contain 543 sandboxed
actions without cache hits. This run qualifies precise source selection on
the native host; conservative selection and foreign execution remain separate.

The shared family helper accepts `editorExecRustcFlags` separately from
`execRustcFlags`. Equal settings reuse the ordinary workspace. Different
settings preserve the target graph while compiling the editor's native macros
with their selected profile. Other families retain their existing defaults
until separately enrolled. Optional compiler tracing captures Cargo test
compilations and the editor's compiler entry point, which remains observable
when rust-analyzer replaces `RUSTC_WRAPPER`.

`aos-dev bazel --family accache rust-project` selects the independent editor
launcher. Its distinct launcher identity also selects a separate private output
base. The packaged-launcher check exports both package roots from the conservative
development snapshot and requires both macro artifacts to match the qualified
editor build byte for byte. Its 135 logged actions execute in Linux sandboxes
without cache hits. The [development report](../tests/evidence/accache-development-editor.json)
retains the run, CLI dispatch check, package export assertion, aggregate check,
and core evaluation result.
The earlier profile reports predate this development routing checkpoint.

The [built-in cfg qualification](../tests/evidence/accache-editor-builtin-cfg.json)
enrolls both the qualification editor and ordinary packaged editor launcher in
the compiler-backed exporter. All 48 configured crates match the captured native
compiler query, which omits `debug_assertions` under these global flags. Both
selected roots retain `rust_analyzer`; package features and macro profiles remain
independent. The packaged route again executes 135 uncached sandbox actions and
authenticates both macro artifacts against the qualified editor build. Both
models still produce the same 253 raw diagnostic rows and 161 distinct
identities, with incomplete inference. The required package, installation and
cache integration outputs are reused unchanged in this checkpoint; their
integration fixture suite was not reexecuted. Persistent editor lifecycle,
complete effective analyzer cfg behavior and foreign targets remain separate
qualification work.

```text
nix-build tools/bazel/tests/accache.nix -A development-editor --no-out-link
```

The check's temporary output base is removed after execution; its exported
project records evidence. Ordinary development keeps its persistent output base.
Full analyzer diagnostics, performance, foreign execution, and production
cutover retain their separate gates. Accache remains daemonless and uses local
disk storage.
