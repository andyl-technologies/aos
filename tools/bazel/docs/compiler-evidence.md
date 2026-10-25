# Compiler invocation evidence

Builds selecting `retainActionGraph` preserve the executed action log and
expanded aquery commands. The response-file expansion must match the executed
command and its declared response-file digest, including when one target has
separate execution and target configurations.

These builds also retain `evidence/compiler-inputs.json`. For every successful
`Rustc` action, it records the exact wrapper argument vector's digest and each
indirect argument, environment, or workspace-status input. Shared file records
preserve UTF-8 contents, byte lengths, and SHA-256 digests. Every file must appear
in that action's executed input inventory with the same digest. Missing files,
changed contents, ambiguous commands, failed compiler actions, and conflicting
contents for a shared path fail the build.

Local disk-cache hits normally leave intermediate outputs unmaterialized. The
evidence launcher option materializes all action outputs so these inputs can be
read before the private build tree is removed. It preserves disabled remote
cache/executor endpoints, offline repository setup, and sandbox policy. Ordinary
builds retain their default materialization behavior. Virtual `FileWrite` inputs
come from aquery's declared contents and undergo the same execution-digest check.

The CLI library proof in `../tests/evidence/cli-compiler-input-retention.json`
uses the frozen lint-qualified CLI workspace. That checkpoint qualifies byte
retention for its source snapshot.

Evidence builds also export `evidence/compiler-invocations.json`. Reconstruction
rechecks the complete executed action inventory and every input digest before
interpreting the pinned wrapper's file syntax, environment precedence, workspace
status values, substitutions, and explicit unstable-feature policy. Repeated
file flags retain every value in each group. Missing inputs, unknown wrapper
flags, duplicate scalar flags, and unretained nested response files fail closed.

Sandbox working-directory, output-base, and execution-root identities remain
explicit symbolic roots. Compiler defaults, semantic equivalence between build
profiles, native ABI, linker closure, and runtime comparisons remain independent
gates. `../tests/evidence/cli-compiler-input-reconstruction.json` binds the
reconstruction checkpoint to its exact source and execution inputs.

The Cargo baseline can retain actual process execution as an independent
wrapper check. The GPL production oracle opts into source-built `strace`
inside the Nix sandbox; the inspection gate requires all requested Rust
compiler calls to reach the declared unwrapped executable and observes the
declared GCC and linker. Concurrent calls are reassembled by process ID;
abbreviated, incomplete, or unsupported records fail closed. Environment
values are omitted. The gate retains tool executable hashes and their Nix
closure inventory alongside the observed commands:

```text
nix-build -A checks.build.bazel.qemu-gpl.cargo-execution-inspection --no-out-link
```

This observes execution, without establishing compiler-default equivalence or
expanding native linker response files. The GPL component documentation links
the retained run and its exact limitations.

The compiler-option conformance gate checks selected interpretation rules
against the declared source-built Rust compiler. Three compilations of a fixed
`no_std` fixture establish that repeated metadata values accumulate: their LLVM
IR matches a combined metadata list and differs from the last value alone.
Metadata therefore remains ordered evidence rather than a scalar override.
Four native `--print cfg` probes check scalar override order and the default
relationship between optimization and debug assertions:

```text
nix-build -A checks.build.bazel.compiler-option-semantics --no-out-link
```

These probes check those specific rules. Complete compiler-default and native
linker equivalence still require their own comparisons.
The [retained conformance report](../tests/evidence/compiler-option-semantics.json)
includes the actual commands, LLVM IR hashes, cfg results, and inspected
source hashes from the pinned Rust archive.

Execution tools have their own compiler configuration. `mkAosBazelWorkspace`
accepts `execRustcFlags` independently of target `rustcFlags`; the launcher
passes them to the pinned rules' `extra_exec_rustc_flags` setting. Omitting
execution flags preserves the existing configuration bytes. Families must
choose their generator and procedural-macro profile explicitly from their
retained Cargo baseline before enrolling in this setting.

```text
nix-build -A checks.build.bazel.execution-profile --no-out-link
```

This check compiles a generator, a procedural macro, and a target libtest in
two configurations. Opposite assertion/overflow settings between execution
and target roles expose accidental forwarding. Six cases check their compiled
behavior; digest-checked wrapper inputs verify all six first-party compiler
actions, and execution events require Linux sandbox execution without cache
hits. Configuration controls reject malformed flags and preserve empty defaults.
The [retained report](../tests/evidence/execution-rust-profiles.json) also records
an actual cfg difference from the historical CLI generator audit: Bazel's
optimized execution default disabled assertions while Cargo's test build
scripts enabled them. This plumbing checkpoint does not enroll existing
families or establish full compiler, native ABI, or linker equivalence.

The [Cargo profile probe](../tests/evidence/cargo-execution-profile-baseline.json)
compiles the same generator, procedural macro and libtest with AOS Cargo and
Rust, without external dependencies. Nine cases pass across the ordinary test
profile, release profile, and the explicit `RUSTFLAGS` used by the CLI editor
oracle. Actual compiler arguments show those editor flags also reach execution
tools, including size optimization and enabled assertion/overflow checks.
The report retains all nine compiler commands and the complete sandbox recipe.
This establishes the minimal Cargo behavior; it does not qualify an actual
rust-analyzer query or complete application graph.

The [rust-analyzer profile probe](../tests/evidence/rust-analyzer-execution-profile-baseline.json)
then runs the declared source-built analyzer over that minimal Cargo workspace.
Actual compiler traces retain both execution-tool builds with default settings
and with the CLI editor oracle's explicit flags. Both analyses finish without
panics, and the explicit size-optimization and assertion/overflow flags reach
both tools. First-party target code is analyzed rather than compiled by this
probe. These observations establish the editor-tool distinction without
claiming full application or whole-model inference equivalence.

The opt-in native source-path adapter maps private execution-root prefixes to
`.` for C compiler source-location strings and debug information. Build scripts
can pass generated files through absolute arguments or response files while
compiling from a separate source repository; the adapter also checks their
`OUT_DIR` context. Explicit caller mappings retain precedence, and the adapter
replaces its process with the declared AOS compiler.

```text
nix-build tools/bazel/tests/native-source-paths.nix -A check -A toolchains --no-out-link
```

The [minimal qualification](../tests/evidence/native-source-path-mapping.json)
passes six cases using real native compilation in a Nix sandbox. Different
execution roots produce byte-identical mapped debug binaries; unmapped controls
differ. Ordinary-directory passthrough, caller overrides, and compiler failure
status also pass. The adapter and its source are included in the realized
toolchain closure. Default toolchain and strict CLI derivation identities are
preserved. The default toolchain is unchanged.

The [full CLI qualification](../tests/evidence/cli-native-source-repeatability.json)
then builds the complete fifteen-program suite twice with this adapter, using
distinct Nix derivations and private output bases. All raw and normally installed
program bytes match without normalization. Both builds retain 1,075 uncached
Linux-sandbox actions and identical requests for all 547 Rust compiler actions.
Loader and CLI help checks pass, and their six runtime dependency paths match
the earlier unmapped Bazel installation. This does not compare every
intermediate native build file or qualify native ABI, runtime services,
shared-cache restoration, or performance.

The separate [Clippy qualification](../tests/evidence/cli-native-source-clippy.json)
passes with the same mapped toolchain and selected source bytes. Its fifteen
Clippy actions and dependencies retain 1,075 uncached Linux-sandbox executions.

```text
nix-build tools/bazel/tests/native-source-paths.nix -A cli-repeatability --no-out-link
```

The conformance check builds the pinned process wrapper from source with AOS
Rust, then compares its actual child arguments and selected environment values
with the reconstruction model. Run it with:

```text
nix-build -A checks.build.bazel.compiler-wrapper --no-out-link
```

The retained helper can also check an existing build while its execution root
is still available:

```text
python3 tools/bazel/tests/retain_compiler_inputs.py \
  --build BUILD_OUTPUT --execution-root PRIVATE_BASE/execroot/_main \
  --output compiler-inputs.json
```

Reconstruct an already retained build without its removed private execution tree:

```text
python3 tools/bazel/tests/reconstruct_compiler_inputs.py \
  --build BUILD_OUTPUT --output compiler-invocations.json
```
