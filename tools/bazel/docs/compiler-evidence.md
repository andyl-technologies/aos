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

The shared Rust-family qualifier selects host-tool profiles independently of
target flags. Ordinary host tools use optimization level 0 with assertions;
release host tools keep level 0 and disable assertions. Editor execution tools
follow explicit global editor flags when present, or the helper's development
preset otherwise. Actual family traces must qualify debug and strip settings;
editor target flags have their own selection.
The [retained default check](../tests/evidence/rust-family-profile-defaults.json)
preserves the pre-change declaration identities of eight explicit families.
The format and static-guest aggregates qualify two actual inherited profiles;
other families still require their own current qualification.

The [initial editor cfg discrepancy](../tests/evidence/editor-builtin-cfg-gap.json)
records a separate gap: the pinned aspect inserts `debug_assertions`
unconditionally, while the current native Cargo model takes it from its
compiler cfg query. The guest's actual optimized query omits it. Selected
diagnostic parity alone does not qualify this built-in cfg behavior.

The [guest cfg qualification](../tests/evidence/guest-editor-builtin-cfg.json)
corrects the explicitly enrolled qualification editor. Its adapter queries the
declared AOS compiler in the native analyzer's flag order, replaces stale
built-in cfg assumptions and preserves configured features, dependency edges,
generated inputs and macro artifacts. Local source roots receive the native
`rust_analyzer` cfg. A required gate compares all 75 configured crates' explicit
built-in cfg fields with the captured native query, alongside ordinary editor
diagnostic parity. All three host-macro artifacts retain their previous bytes.

The [accache cfg qualification](../tests/evidence/accache-editor-builtin-cfg.json)
also enrolls its qualification editor and ordinary packaged editor route. All
48 configured crates match the native query, both roots retain their expected
features, and both macro artifacts match the independent editor profile build.
The ordinary route executes 135 uncached sandbox actions. Its selected
diagnostic rows still match, with incomplete inference.

The [shared-library qualification](../tests/evidence/shared-profile-editor-qualification.json)
enrolls all 28 configured crates and five selected roots. Its editor comparison
also matches native whole-model statistics, with complete inference and no
diagnostic rows in this selected family. All five test targets and both host
macros pass the independent captured-compiler scalar profile audit.

The [quota cfg checkpoint](../tests/evidence/quota-editor-profile-cfg.json)
checks all 12 configured crates in both qualification and packaged editor
routes. Whole-model inference remains complete with no diagnostic rows, and
the ordinary test compiler profiles and qualified VM identities are unchanged.

The [static activation adapter checkpoint](../tests/evidence/activation-crucible-editor-profile-cfg.json)
checks all 119 configured editor crates and separately audits the actual seven
macro compilations. Its native analyzer trace uses optimization 0, debug
information 2 and no stripping, unlike the earlier helper preset. The family
now selects those settings explicitly. `retainEditorActionGraph` retains
digest-checked compiler inputs from the editor's own execution; its required
profile gate rejects target static flags in host macros. The minimal native
fixture's debug-information-0 result does not qualify other families. Their
full native editor traces still need independent checking.

`mkAosBazelWorkspace.editorCfgFlags` selects this adapter; `null` preserves the
existing exporter during rollout. The adapter currently requires the default
native target and rejects foreign target configurations. Other families and
their ordinary development launchers still require enrollment. Complete effective
analyzer cfg behavior for arbitrary flags remains a separate acceptance check.

The selected compiler audit also supports release targets and source-qualified
Cargo names. The [release audit checks](../tests/evidence/rust-release-profile-auditor.json)
accept the retained guest requests and reject incorrect optimization,
assertions, ambiguous names and a missing source mapping. These are checks
against actual retained requests, not additional compiler executions.

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

CLI ordinary and fleet oracles also require execution inspection. Their
temporary Cargo baseline traces only the offline compilation phase, retaining
`compiler-exec.log` and a matching `compiler-compile-arguments.jsonl` snapshot.
Tests subsequently execute without tracing. The profile gate fingerprints all
source compilation requests, preserving arguments, directory, Cargo metadata,
and multiplicity while ignoring record ordering. It requires the full profiled
source inventory to match the independently observed phase and binds the
observed compiler's SHA-256 to the native-default conformance compiler.
Later compiler queries without source files do not change this inventory;
the inspector separately checks every compiler request in the traced phase.
Run either `default.cargo-execution-inspection` or
`fleet.cargo-execution-inspection` in `tools/bazel/tests/aos-cli.nix` to expose
the inspection separately from case and profile parity. Observed GCC/linker
commands and toolchain closure stay available for further native qualification.

CLI requested-command inspection explicitly retains undecoded `???(` task
records in `execution_capture.unresolved_task_records`; they never contribute
an execution or satisfy a requested command. The ordinary parser mode still
rejects them. Capture with any such record has `complete = false`, and the
separate `default.cargo-complete-execution` and `fleet.cargo-complete-execution`
gates fail. Earlier ordinary and fleet captures each contained an undecoded
task record; kernel syscall filtering also reproduced the failure and is not
a qualified repair. The latest retained ordinary and fleet captures contain
no undecoded records and pass strict parsing. This qualifies those concrete
captures without establishing a general tracer repair. `compiler-trace-conformance` exercises 96 queries, eight linked
compilations and executions, exact requested-command coverage, and strict
rejection of undecoded records. This bounded coverage must not be reported as
a complete execution stream when unresolved records are present, or complete
native compiler/linker equivalence. The
[retained public CLI qualification](../tests/evidence/cli-observed-native-execution.json)
binds 639 ordinary and 645 fleet source requests to independently observed
compiler executions. It retains the earlier incomplete captures as strict
negative controls, alongside the clean current captures.

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

Native target and execution roles can be recovered from compiler artifact
relationships even when Cargo writes both roles into the same directory.
`qualification/native_compiler_units.py` follows recorded `--extern` paths from
explicit first-party target roots and custom-build/procedural-macro execution
roots. It rejects missing producers, ambiguous outputs, unreachable units, and
artifacts shared by both roles. It preserves `proc_macro` sysroot references
and separately records capability queries and probes without Cargo artifacts.
The model currently accepts ordinary Linux Rust artifact names; unsupported
output forms fail closed.

The [retained native artifact audit](../tests/evidence/native-compiler-artifact-roles.json)
classifies all 631 ordinary and 637 fleet CLI compiler units. Optimization
settings are checked after role classification. Eight focused tests cover role
propagation and rejected inputs. This audit qualifies native role assignment;
Bazel unit matching and complete compiler, linker, ABI, and runtime equivalence
still require their own checks.


CLI ordinary-test profile gates now enroll stripping and complete external
unit pairing. The [retained comparison](../tests/evidence/cli-strip-profiles.json)
uses artifact-derived native roles and rejects missing or duplicate dependency
units. Exact pinned build-system helpers are retained separately and must use
execution configurations. Extra native C-facing artifact kinds remain explicit;
the Rust library comparison does not establish their ABI or package behavior.

`qualification/strip-semantics.nix` is a required dependency of profile gates
that enable strip comparison. Five actual native Rust compilations check the
implicit `none` default, explicit `none`, debug stripping, and a linked C
constructor compiled with debug information while Rust emits none. The
implicit and explicit controls have identical bytes; debug stripping removes
DWARF while retaining ordinary symbols and program behavior. This establishes
the specific normalization used by the profile verifier, without normalizing
application artifacts or qualifying other compiler defaults.

CLI gates additionally require `qualification/profile-semantics.nix`. Thirteen
runtime variants test unoptimized and size-optimized assertion/overflow defaults,
boolean aliases, last scalar overrides, and positive and negative controls.
Every variant produces identical bytes through the source-built wrapped and
unwrapped compiler. Five isolated flag comparisons require identical fixture
binaries. Omitted and explicit zero debug information produce identical bytes;
DWARF checks inspect the fixture source's entries because linked standard-library
objects can contribute their own debug information. A debug-enabled control must
retain the fixture's entries. Implicit and explicit native targets also have
identical compiler cfg inventories.

The profile verifier binds the conformance compiler's SHA-256 to each actual
Bazel Rust compiler input and rejects targets outside the probed native target.
Four rejection tests cover compiler/digest drift, missing or ambiguous inputs,
unexecuted compilers, failed probes, and foreign targets.
The [native-default receipt](../tests/evidence/cli-native-profile-defaults.json)
retains all probe results and bindings for 635 ordinary and 641 fleet Rust
compiler actions, reusing the prior application test artifacts and native
baselines. That historical receipt predates the independent native execution
binding described above. These checks support the selected profile default
interpretations; incremental compilation, codegen-unit defaults, procedural-macro
linking, complete application artifact/ABI/runtime equivalence, and other
platforms remain separate acceptance work.
