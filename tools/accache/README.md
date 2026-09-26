# accache

A daemonless compiler action cache for AOS Nix application builds. Every
invocation opens the shared directories itself. There is no host service,
socket, daemon lifecycle, or shared in-memory compiler configuration.

## Development use

```sh
bash ./aos-dev cache init
bash ./aos-dev build package aos --no-out-link
bash ./aos-dev --no-rust-incremental build package aos --no-out-link
bash ./aos-dev --release build package aos --no-out-link
```

Accache is enabled by default in development mode. `--no-accache` disables it;
release mode disables all shared cache configuration. Existing Go, Bazel, Cargo target, and Rust incremental
options remain independent. Rust incremental compiler invocations bypass
accache and continue using the configured persistent incremental directory.
Use `--no-rust-incremental` for action-cache hits on workspace crates as well
as nonincremental dependencies. Keeping both enabled favors incremental reuse
while editing workspace crates and action-cache reuse for their nonincremental
dependencies. These switches do not select a Cargo optimization profile or
guarantee faster generated binaries; application builders retain their configured
profiles. GCC, LLVM, Rust, Go, Java, and other toolchain builds keep their ordinary
identities. Building accache itself also has shared caching disabled.

`mkCargoPackage` configures `RUSTC_WRAPPER` for application builds when both
`sharedAccacheDir` and `sharedAccacheStateDir` are configured. Application
recipes using CMake can set `cacheCCompilers = true` on `mkDerivation`; dwarves
and BoringSSL currently do. This adds GCC/G++ compiler launchers only when
accache is enabled, using the ordinary compiler closure. Other C/C++ builders
can use `pkgs.mkAccacheEnvironment` with their exact compiler paths and roots.
Build systems without a compiler launcher must invoke
`accache /absolute/compiler/path ...` explicitly. Generic `cc` calls are not
replaced globally.

The CLI mounts `AOS_DEV_ACCACHE_DIR` and `AOS_DEV_ACCACHE_STATE_DIR` (defaults:
`/aos-build-cache/accache` and `/aos-build-cache/accache-state`) into the sandbox.
They map to `accache` and `accache-state` under `AOS_DEV_CACHE_DIR`, defaulting
to `${XDG_CACHE_HOME:-$HOME/.cache}/aos-dev` when its parents are traversable.
Private homes automatically fall back to `/var/tmp/aos-dev-cache-UID`; no root
setup is required. To keep physical storage under a private XDG directory,
an administrator can optionally
bind-mount that XDG directory at a traversable alias and set
`AOS_DEV_CACHE_DIR` to the alias; home permissions can remain private.
Existing `/var/tmp/aos-dev-cache-UID` trees are left intact; set
`AOS_DEV_CACHE_DIR` explicitly to keep using one. Derivations
receive the configured paths in environment variables; the host backing
path does not enter their identities.

## Compiler contract

The Nix helper constructs `ACCACHE_MANIFEST` from the daemon's realized
reference graph. Each compiler, wrapper, loader, sysroot, and transitive
library in the declared closure contributes its store path and NAR hash.

```json
{
  "schema": 1,
  "compilers": {"/nix/store/…/bin/rustc": "rust"},
  "closure": [{"path": "/nix/store/…", "narHash": "sha256:…"}],
  "remove_environment": ["out", "src", "NIX_BUILD_TOP"],
  "read_roots": ["."]
}
```

Compiler arguments, current directory, effective environment, discovered file
contents, CPU features, output names, and the manifest participate in the key.
Dependency discovery runs on every lookup. Creating a newly preferred header
or changing `__has_include` results therefore invalidates the action even if
previously discovered files did not change. Discovery repeats after a miss;
changing inputs prevent publication.

`remove_environment` removes variables from **execution and hashing**. It
cannot hide a variable from the key while leaving it visible to the compiler.
The helper removes derivation bookkeeping and inherited jobserver variables.
Packages using those variables intentionally must override the list.

Proc macro consumers, compiler plugins, and Clang assembly (including `.S`
files with assembler `.include` directives) need declared `read_roots`; those
trees are hashed recursively. GNU `.S` builds use a separate assembler probe
to discover `.include` inputs that the C preprocessor cannot see. Cargo's
`OUT_DIR` and `CARGO_MANIFEST_DIR` are also covered for proc macro consumers.
Native library search directories and explicit library/module/profile inputs
are tracked.
The package author must declare every extension-readable mutable input and
must not cache compiler extensions with undeclared side effects. This is an
input contract, not an additional filesystem sandbox. Full tree hashing can
produce conservative misses and can be expensive for large generated trees.
Literal `.include` and `.incbin` directives in C/C++ inline assembly also
receive extra dependency discovery when they appear in preprocessed text.
GNU compilers use an assembler depfile probe only for those actions; Clang
requires declared `read_roots`. Disable accache for actions that construct
these directives from separate string fragments; the literal check cannot
discover them.

## Frontend compatibility

The complete pinned sccache GCC/Clang/Rust argument tables and parsers are
extracted into [frontend](frontend/UPSTREAM.md). Cacheable Rust invocations
with nested response files expand those files before execution, matching
sccache's frontend even though direct rustc rejects them. Every referenced
response file is fingerprinted so an inner edit invalidates the action.
Other compiler arguments are passed unchanged. Unsupported invocations run
the compiler and record a bypass reason. Non-UTF-8 arguments also run unchanged.

Covered output families include ordinary C/C++ objects, depfiles (including
GCC/Clang `-Wp,-MD` and `-Wp,-MMD` and GCC `-Xpreprocessor -MD`), split debug
files, coverage notes, preprocessed source, assembly, PCH, explicit Clang
modules, and serialized Clang diagnostics. GCC coverage includes SARIF and
plain HTML diagnostic reports, numbered tree, RTL, IPA, language, debug,
early-debug, and analyzer dumps (including graph and compressed JSON forms),
Ada and Go specs, final instruction dumps, and compressed optimization
records. Joined GCC `-d` debug dumps are included. Rust coverage includes
nonincremental rlib/staticlib, metadata, dep-info, unpacked split debug
`.dwo` files, and `-Csave-temps=yes` bitcode, object, and saved metadata files.
Rust extern/native dependencies and proc macro consumers are covered by the
input contract above.
GNU assembler `--MD` output forwarded through `-Wa` or `-Xassembler` is
tracked for GCC and Clang with an external assembler. Clang's generated
assembly path can make that depfile nondeterministic; a warm hit restores the
exact cold artifact.

Incremental Rust, executable/proc-macro compilation, ordinary linking, and
upstream parser exclusions bypass. Frontend parsing compatibility is not a
claim of support for every compiler/version/platform, nor for arbitrary new
side-effect flags. This package targets the AOS Linux compiler toolchains.
Rust `--emit` forms that name individual output paths bypass as in the pinned
sccache frontend; the compiler still writes those requested files normally.
Clang's driver-level `-dependency-file` option also bypasses: the driver ignores
it while pinned sccache expects a file at that path and fails during publication.
Clang `-Wp` requests that mix a dependency output with other forwarded CPP
options bypass because the driver does not consistently use the forwarded path.
Rust `-Csave-temps=yes` stores files inside randomly named `rmeta*` and `rustc*`
directories as well as top-level bitcode and object files. All wrapped Rust
compilers using one accache state directory take a shared lock for their output
directory; save-temps actions take it exclusively while discovering and
publishing their files. This preserves the complete file output set on warm
hits, including with unpacked split debug. Pinned sccache accepts the flag but
omits those files on warm hits. Compiler processes outside this wrapper do not
participate in the lock, so do not mix them with cached save-temps actions in
one output directory. Empty rustc temporary directories are not cache artifacts.
GCC dumps and SARIF reports using separate `-dumpbase` or `-dumpdir`
options bypass, as they do in the pinned sccache frontend. The joined
`-dumpbase=foo` spelling instead acts as `-d` debug letters; its dumps are
tracked. GCC 16's documented
`-fdiagnostics-add-output` and `-fdiagnostics-set-output` SARIF sinks are cached
with their report files. Parameterized text and plain HTML sinks are cached.
HTML diagram modes are cached with SVG embedded in the report; the action key
includes `PATH`, which selects the AOS-built `dot` used for diagrams. Unknown
sink specifications bypass.
Specialized GCC dump families outside tree, RTL, IPA, language, statistics,
debug, early-debug, and analyzer still bypass when they select implicit
filenames. Explicitly named GCC dumps and optimization reports are cached with
their requested output files.
GCC Ada spec generation has a separate working-directory scope for `.ads`
files: transitive headers can create names unrelated to the selected object.
The scope lock prevents concurrent wrapped writers from being attributed to
the wrong action. Do not run an unwrapped Ada binding generator concurrently
in the same working directory.
GCC `-time[=file]` bypasses caching because its timing output is invocation
specific and the file form appends to an existing file.

## Storage and concurrency

```text
cache/ac/<first-two-hex>/<sha256>     REAPI ActionResult
cache/cas/<first-two-hex>/<sha256>    content-addressed blobs
state/locks/<action>                 per-action OS file lock
state/locks/rust-dir-<sha256>        shared/exclusive Rust output-directory lock
state/events/<unique>.json          immutable invocation provenance
state/latest/<slot>                 prior identity for explanations
```

The cache uses Bazel's disk layout and REAPI v2 protobuf field numbers. Action
inputs currently describe a local Nix inventory; they are **not yet a remote
executor input tree**. Remote cache transports and remote execution are not
implemented. Bazel and accache do not share compiler action keys.

Atomic renames publish blobs before action results. Readers verify content
digests and the expected output set, then stage independent output copies.
A missing/corrupt entry causes recompilation. Per-action locks collapse
concurrent identical misses; different actions do not share a global lock.
Different toolchains and worktrees can use the same directories because their
contracts and inputs partition the keys. Absolute Cargo target destinations
are mapped through the current invocation, never trusted from cache data.

Use shared cache roots only among trusted build users. Content hashing detects
accidental corruption; it is not authentication against malicious writers.
Default ACLs configured by `cache init` allow different Nix build users to
write entries. Restored artifacts respect destination ACLs and the build umask.
`aos-dev cache accache` provides status, entries, builds, prune, compact, and
clear commands. Global usage/prune/clear include the action cache. Cleanup
leaves the separate state directory intact, retaining provenance and locks.
Do not unlink active lock files or remove the state tree during builds.

## Inspection

```sh
ACCACHE_DIR=/path/cache ACCACHE_STATE_DIR=/path/state accache stats
ACCACHE_DIR=/path/cache ACCACHE_STATE_DIR=/path/state accache explain
ACCACHE_DIR=/path/cache ACCACHE_STATE_DIR=/path/state accache explain ACTION_SHA256
ACCACHE_DIR=/path/cache ACCACHE_STATE_DIR=/path/state accache provenance
```

Stats and explanations are JSON; provenance is JSON Lines. Events distinguish
hits, misses, bypasses, failed compilation, unstable inputs, and write errors.
They retain arguments, input hashes, effective environment hashes, timestamps,
and the build output path when available. `ACCACHE_DERIVATION` optionally
records a `.drv` path without making it an action-key input. The build output
can also be resolved to its deriver using Nix. Command blobs contain the actual
effective environment; treat cache storage with the same care as build inputs.

`ACCACHE_VERBOSE=1` prints each outcome. `ACCACHE_DISABLE=1` or an absent
`ACCACHE_DIR` runs the compiler directly.

## Validation

```sh
bash ./aos-dev --release build check build.accache --no-out-link
```

`checks.build.accache` builds the compiler wrapper and a pinned, test-only
sccache executable from source. Its private sccache server runs inside the test
sandbox and is stopped in `finally`. No developer cache/server is used. The
check provides the AOS-built Graphviz `dot` and requires embedded SVG in the
direct-compiler HTML reports for diagram cases.

The suite compares direct compilation, sccache, and accache using identical
paths, flags, working directories, and environments. It checks exit status,
stdout, stderr, the complete generated-file inventory, executable bits, and
artifact bytes. GCC PCH files are process-dependent: that fixture checks file
presence and exact cold-to-warm replay in each cache, while PCH consumer objects
still receive byte-for-byte comparisons. It deletes outputs before warm runs,
asserts cache hits, and changes dependencies to require misses. Separate tests
exercise corruption, concurrent identical requests, PCH/modules, native
libraries, proc macro file reads, persistent target paths, and source/header
names containing spaces. Clang PCH coverage includes its `-Xclang -emit-pch`
driver form and a header mutation.

The nested Rust response fixture uses pinned sccache as its output reference:
direct rustc rejects an inner `@file`, while sccache expands it. The fixture
mutates that inner file and requires a miss with provenance naming the change.
Cargo-style Rust cases cover extra filenames, metadata disambiguation, panic
mode, multiple codegen units, and `--cfg` with `--check-cfg`; output names and
bytes must match direct rustc and pinned sccache on cold and warm runs.
The frontend check also requires incremental Rust to bypass caching.
An oracle case verifies that sccache's warm `-Csave-temps=yes` hit omits
bitcode and saved metadata files while accache restores the complete file set
from a warm hit. Frontend checks also cover save-temps with metadata-only,
staticlib, and unpacked split debug output, plus concurrent writers sharing a
Rust target directory.
Unpacked Rust split debug cases check four rlib `.dwo` files and one staticlib
`.dwo` file: pinned sccache omits them on warm hits, while accache restores
their bytes and lists them in action provenance. Their changing CGU names are
discovered after compilation within the declared output directory.
Another oracle case changes a GNU assembler `.include` under a `.S` file:
pinned sccache incorrectly replays the old object, while accache reports the
changed include in its miss explanation and returns the new compiler output.
Four more cases mutate a binary read by C inline assembly in GCC/Clang `.c`
and `.i` compilations. Pinned sccache again replays stale objects; accache
misses and names the changed binary input.
Clang and Rust profile cases generate two real instrumentation profiles each
and require a miss naming the changed `.profdata` file, followed by a warm hit
for each profile.

The suite asserts several pinned sccache output omissions: implicit `.d` files
on warm `-MMD` hits without `-MF`, GCC `-aux-info` files, Clang serialized
diagnostics, and the empty `.rmeta` generated by staticlib metadata actions.
Each exception names the exact fixture and missing file, and fails if the
oracle changes. Accache must restore every file produced by the direct compiler.
The report lists these oracle omissions per revision.
GCC `-fdump-internal-locations` changes its stderr whitespace when sccache
compiles preprocessed input; the oracle records that exception while requiring
accache's cold and warm streams to match direct GCC exactly.
