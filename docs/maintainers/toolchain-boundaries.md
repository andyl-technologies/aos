# Toolchain qualification boundaries

`checks.qualification.toolchain-hermeticity` is a mandatory dependency of
`checks.qualification.all`. It combines the exported native toolchain audit
with an ordinary native package sandbox probe. Both checks also participate in
`checks.build.all`. They are source regression gates; passing them does not
issue a release admission or establish that a compiler is free of codegen bugs.

## Running the checks

```text
nix-build -A checks.qualification.toolchain-hermeticity --dry-run
nix-build -A checks.build.toolchain-boundaries.verifier
nix-build -A checks.build.toolchain-boundaries.bootstrap --keep-failed
nix-build -A checks.build.native-sandbox-boundary --keep-failed
nix-build -A checks.qualification.toolchain-hermeticity --keep-failed
```

The dry run matters during qualification: missing exported tier tools must be
built before they can be inspected. Do not substitute a smaller inventory or
silently skip unavailable outputs. Individual tier checks allow diagnosis with
already available outputs without launching the entire bootstrap ladder.

Nix caches successful checks. A sandbox result from another daemon configuration
does not validate the current executor. Rebuild the sandbox check with `--check`
when its output already exists, on every qualification executor and after sandbox
configuration changes; preserve that execution log with campaign evidence.

## Export policy

Previous tiers are permitted inputs while constructing a successor. That does
not permit a successor's public executable wrapper to keep invoking its
predecessor's shell or assembler. The inventory imports the actual tier values
from `stdenv/toolchains/default.nix`; its optional inventory export does not
alter any compiler's derivation inputs. It covers the bootstrap output and every
tier in the active native ladder, including its architecture transition.

Each tier audit:

- Rejects missing outputs and failed inspections.
- Checks executable shebangs against that tier's exported output roots,
  resolving symlinks before allowing an interpreter.
- Rejects executable aliases into other tiers and ambient `env` interpreters.
- Asks the exported GCC driver which assembler and linker it selects with an
  empty tool search path, and compares the resolved paths with its declared
  binutils.
- Records violations in `report.json` and fails instead of creating passing
  evidence. Use `--keep-failed` to retain this report after a failure.

Read-only build metadata containing old store paths is not, by itself, an
executable dependency. The audit does not erase those references. Multi-output
libraries are included in the permitted tier roots.

The sandbox probe checks common host tool/header paths, rejects a foreign
injected shell, and compiles and runs a small C program. This is a regression
probe for known exposure, not proof against every namespace escape. Explicit
Linux-hosted and Darwin cross environments still need their existing platform
checks; this native ladder audit does not certify their full executable closure.
ELF loader search paths, process-wide library overrides, binfmt handlers, and
tool subprocesses chosen from script bodies require additional tracing and gates.

## September 9, 2026 triage

The initial checks intentionally expose existing violations. Do not add an
allowlist merely to make qualification green:

- Bootstrap GCC 2.95.3's wrapper invokes TCC-built Bash and selects TCC-built
  binutils, despite exporting rebuilt stage-5 versions of those tools.
- Final GCC 16's wrapper invokes the previous tier's Bash. Its selected
  assembler and linker are the declared binutils 2.41; no ancient binutils
  fallback was observed in that final compiler.
- Installed auxiliary scripts in several tiers use ambient shell paths.
- The inspected Nix sandbox injects a non-AOS BusyBox as its default shell.
  The ordinary probe could not see the checkout, host compiler, or host headers.

Repair the internal-build/public-export split before switching wrapper shells:
using a tier's new Bash while building that same Bash creates a dependency
cycle. Rebuild and validate exported tools after establishing that split. Merely
scrubbing references or changing PATH does not repair embedded wrapper paths.

The crash investigation does not yet establish causation. Saved Rust 1.88-build
crash mappings identify the expected Rust 1.87 compiler, LLVM, and current glibc,
not an old dynamically loaded libc. All twenty assembler SIGSEGV records in the
inspected thirty-day journal were binutils 2.15 configure probes. Available
kernel logs showed older OOM kills but no matched machine-check/ECC reports;
the current corrected/uncorrected EDAC counters were zero. These observations
do not prove hardware health or compiler correctness. The latest qualification
failure was a Java compiler `ClassCastException` while building OpenJDK 10,
which remains a separate unresolved failure.
