# Design: Replacing /bin/sh in the Bootstrap Chain

## Problem Statement

Every stage in the AOS bootstrap chain currently uses `builder = "/bin/sh"` in
`builtins.derivation`. While Nix provides `/bin/sh` inside its build sandbox
(it is NOT the host's shell), the user considers this impure: the goal is ZERO
host filesystem dependencies. Everything must trace back to the 229-byte hex0
seed and 618-byte kaem seed.

## Nix Builder Mechanics

`builtins.derivation` requires a `builder` field — an absolute path to an
executable. The Nix daemon:

1. Creates the sandbox (tmpfs, isolated network, etc.)
2. Sets environment variables: `$out`, `$TMPDIR`, `$NIX_BUILD_TOP`, `$PATH=""`,
   plus any variables defined in the derivation attributes
3. Executes `builder` with `args` as argv
4. The builder inherits all environment variables set by the daemon

Key insight: **the builder can be ANY executable**. It does not have to be a
shell. It just needs to be an ELF binary (or script with `#!` pointing to one)
at a known path.

Special case: `builder = "builtin:fetchurl"` is handled by the Nix daemon
itself — no external binary needed. Stage 0 already uses this correctly.

## kaem Capabilities (Full Version from mescc-tools)

The "full" kaem (compiled during stage 1 from mescc-tools) supports:

| Feature | Supported | Notes |
|---------|-----------|-------|
| Execute commands | Yes | Fork/exec, whitespace-separated argv |
| `${VAR}` expansion | Yes | Environment variable substitution |
| `${VAR:-default}` | Yes | Conditional fallback |
| `$@` | Yes | Command-line arguments after `--` |
| `set -e` / `--strict` | Yes | Exit on error |
| `set -x` / `--verbose` | Yes | Trace execution |
| `set -a` | Yes | Export all variables |
| `cd` | Yes | Built-in chdir |
| `pwd` | Yes | Built-in |
| `echo` | Yes | Built-in |
| `if/then/else/fi` | Yes | Based on exit status |
| Environment assignment | Yes | `FOO=bar` syntax via `add_envar()` |
| `unset` | Yes | Remove env vars |
| `exec` | Yes | Replace process |
| `alias` | Yes | Command aliases |
| Double-quote strings | Yes | With backslash escapes |
| `#` comments | Yes | Line comments |
| Pipes (`\|`) | **No** | |
| Redirects (`>`, `<`) | **No** | |
| Loops (for, while) | **No** | |
| `$VAR` (no braces) | **No** | Only `${VAR}` format |
| Command substitution | **No** | No `$(cmd)` or backticks |
| Arithmetic | **No** | |
| Functions | **No** | |
| Globbing (`*`, `?`) | **No** | |
| `case` / `switch` | **No** | |

The kaem-seed (618 bytes) is much more limited — it only reads lines and
executes them as commands. No variables, no conditionals.

## Stage-by-Stage Analysis

### Stage 0: Seeds (hex0 + kaem)

**Current builder:** `builtin:fetchurl`
**Change needed:** None. Already pure — no /bin/sh dependency.

### Stage 1: mescc-tools

**Current builder:** `/bin/sh` with a complex script
**Shell features used:**
- `set -eu` (strict mode, errexit)
- `${seeds.hex0}` (Nix interpolation, not shell — fine)
- `cd "$TMPDIR"` (cd with variable)
- `$MKDIR`, `$LN` (variable expansion)
- `for f in ...; do ... done` (loops)
- `case "$name" in ... esac` (pattern matching)
- `''${f##*/}` (parameter expansion — shell substring)
- `if [ ... ]; then ... fi` (conditionals)
- `echo` (output)
- `[ -f "$f" ]` (file test)

**Analysis:** This is the critical "chicken and egg" stage. We need the
mescc-tools kaem to replace /bin/sh, but mescc-tools IS what builds kaem.

**Key observation:** The actual compilation (hex0 -> hex1 -> ... -> kaem)
is already driven by kaem scripts from stage0-posix. The /bin/sh wrapper
only does:
1. Compile mkdir and symlink from hex0 assembly (2 commands)
2. Create directory structure with the hex0-compiled tools (simple commands)
3. Symlink source files (simple commands)
4. Run kaem scripts (3 commands)
5. Copy outputs to $out (using mescc-tools-extra cp/chmod)

**Strategy: Use kaem-seed (from stage 0) as the Nix builder.**

The kaem-optional-seed (618 bytes) is already downloaded in stage 0 via
`builtin:fetchurl`. It is a working script executor — no `/bin/sh` needed.
There is no chicken-and-egg problem.

```nix
builder = "${seeds.kaem}";
args = [ "--strict" "--file" "${buildScript}" ];
```

Where `buildScript = builtins.toFile "build-mescc-tools.kaem" ''...'';`
with all Nix store paths pre-interpolated at eval time.

**The `$out` / `$TMPDIR` problem and solution:**

kaem-seed cannot expand environment variables — it only reads lines and
executes them as literal commands. But `$out` and `$TMPDIR` are only known
at build time (set by the Nix daemon).

Solution: **two-phase build within a single derivation.**

1. **Build phase** — kaem-seed runs the stage0-posix kaem scripts. All
   source paths are pre-baked by Nix interpolation. Build outputs go to
   relative paths in CWD (Nix sets CWD to `$TMPDIR`).

2. **Install phase** — kaem-seed invokes the **freshly-built full kaem**
   (which DOES support `${VAR}` expansion) to run an install script:

   ```kaem
   # Last line of the build script (executed by kaem-seed):
   ./mescc-tools/bin/kaem --strict --file /nix/store/...-install.kaem
   ```

   The install script (a separate `builtins.toFile`) uses full kaem's
   `${out}` expansion:

   ```kaem
   ${mescc-tools-extra}/bin/mkdir ${out}
   ${mescc-tools-extra}/bin/mkdir ${out}/bin
   ${mescc-tools-extra}/bin/cp ./M2-Planet ${out}/bin/M2-Planet
   ...
   ```

   Here `${out}` is expanded by full kaem at build time, while the
   `/nix/store/...-install.kaem` path was baked in by Nix at eval time.

This approach uses **zero `/bin/sh`** — only the two seed binaries (hex0
and kaem) plus tools compiled from source during the build.

### Stage 2: GNU Mes

**Current builder:** `/bin/sh`
**Shell features used:**
- `set -eu`, `export PATH=...`, `export VAR=val`
- `cd`, `mkdir -p`, `chmod -R`, `tar xzf`, `cp`, `cat > file << 'EOF'`
- `if [ ! -f ... ]`, conditional copies
- Functions: `mescc_compile()`, `m1_assemble()`
- `rm -f`, `2>/dev/null || true`
- For loops, variable assignments

**Strategy: Use stage 1 kaem as builder**

After stage 1, we have the full kaem with `${VAR}` expansion, `cd`, `echo`,
`if/then/else/fi`, `set -e`, and environment variable assignment. This covers
most needs.

However, Stage 2 uses features kaem lacks:
- **Heredocs** (`cat > file << 'EOF'`) — Use `catm` or pre-baked files via
  `builtins.toFile` instead
- **Functions** — Inline the commands or use separate kaem subscripts
- **Pipes** (`2>/dev/null || true`) — Kaem has no redirects; remove stderr
  suppression or use wrapper tools
- **For loops** — Kaem has no loops; enumerate commands explicitly or use a
  helper program
- **`tar xzf`** — Use mescc-tools `ungz` + `untar` (already done in some stages)
- **`chmod -R`** — mescc-tools has `chmod` but not recursive; use `find` or
  enumerate files
- **Parameter expansion** (`''${f##*/}`) — Not in kaem; use basename tool
- **`mkdir -p`** — kaem's environment won't have mkdir; use mescc-tools mkdir
  or build one

**Practical assessment:** Stage 2 is too complex for kaem alone. The script
uses shell functions, heredocs, for loops, complex conditionals, and command
chaining that kaem fundamentally cannot express.

**Recommended approach:** Write a small C "builder driver" program, compiled
by the stage 1 tools (M2-Planet or hex2), that can execute a sequence of
commands from a file. This is essentially a more capable kaem with a few
additions:
- Simple for-each-line loop over a file list
- Redirect stdout to a file (for the config.h creation)
- Exit status checking

Alternatively, use **bash 2.05b from posix-tools** — but that creates a
circular dependency since posix-tools depends on TCC (stage 3), which
depends on Mes (stage 2).

**RECOMMENDED: Use a kaem script with pre-baked Nix paths + helper tools**

Refactor the stage 2 build to:
1. Use `builtins.toFile` to create config.h (not heredoc)
2. Enumerate all commands explicitly (no loops/functions)
3. Use `catm` for file concatenation (already used)
4. Use mescc-tools `mkdir`, `cp`, `chmod` for file operations
5. Accept that some commands will be very verbose (all 60+ M2-Planet
   source file arguments spelled out)

This is feasible because the actual compilation steps are deterministic
and fully known at Nix evaluation time.

### Stage 3: TinyCC

**Current builder:** `/bin/sh`
**Shell features used:** Similar to stage 2 plus:
- Shell functions (`rebuild_mes_libc()`) with local variables
- Complex for loops over file lists
- Arithmetic (`$((n + 1))`)
- Multiple sequential compilations with varying flags

**Strategy:** Same as stage 2 — kaem with pre-baked paths. The
`rebuild_mes_libc` function can be replaced by enumerating all ~258
compile commands explicitly. This is verbose but deterministic.

The `libcSourceList` is already defined in Nix — at evaluation time, we
know every file path. A kaem script can list all 258 `tcc -c -D... -o
objN.o source.c` commands one per line.

### Stages 4-16: binutils/GCC/glibc chain

**Current builder:** `/bin/sh`
**Shell features used:**
- `set -eu`, `export PATH=...`
- `cd`, `chmod -R u+w .`, `find ... -exec chmod +x {} +`
- `tar` extraction via mescc-tools
- `./configure` (requires a POSIX shell)
- `make -j$(nproc)`
- `sed -i` (used heavily for patching)
- `make install`
- For loops, conditionals
- `ln -sf`, `cat > file << WRAPPER`

**Critical insight:** Starting at stage 4, `./configure` scripts require a
**real POSIX shell**. Configure scripts use:
- Variable expansion, command substitution `$(...)`, backticks
- Functions, loops, case statements
- Pipes, redirects
- `test` / `[` commands
- Trap handlers

kaem CANNOT run configure scripts. Period.

**Strategy: Use bash from posix-tools as the builder**

The posix-tools stage (between stage 3 and 4) builds bash 2.05b from
TCC. This bash is fully self-hosted — compiled from source by our own
TCC with our own Mes libc.

For stages 4-16:
```nix
builder = "${posixTools}/bin/bash";
args = [ "-c" "..." ];
```

This is the natural and correct approach. bash 2.05b IS built from
source in our chain. It is not /bin/sh from the host or the Nix sandbox.

### POSIX Tools (between stages 3 and 4)

**Current builder:** `/bin/sh`
**Shell features used:**
- `set -eu`, `export PATH=...`
- File extraction via mescc-tools
- Direct TCC compilation commands
- `mkdir -p`, `cp`, `chmod`
- For make/sed: `catm` for creating files, then `make` invocations
- For the composed output: for loops copying binaries

**Strategy:** The individual tool builds (make, sed, grep, patch) are
simple enough for kaem:
- Extract with mescc-tools
- Enumerate compile commands
- Link
- Copy output

The composed posix-tools output derivation uses a for loop that kaem
cannot handle, but it can be replaced by enumerating each copy command
explicitly.

**For bash 2.05b:** This is the key bootstrapping target. bash itself
is built by direct TCC compilation (like make, sed, grep), so kaem can
drive this build. Once bash exists, it becomes the builder for everything
after.

## Recommended Implementation Plan

No phasing needed — zero `/bin/sh` from the start:

```
Stage 0:  builtin:fetchurl          (Nix daemon, no binary needed)
          hex0 (229 B) is the ONLY opaque binary
          kaem is COMPILED FROM SOURCE by hex0 (kaem-minimal.hex0)
Stage 1:  ${seeds.kaem}             (kaem compiled from hex0 source)
Stage 2:  ${mescc-tools}/bin/kaem   (full kaem, built in stage 1)
Stage 3:  ${mescc-tools}/bin/kaem   (full kaem)
Posix:    ${mescc-tools}/bin/kaem   (full kaem, per-tool sub-derivations)
Stage 5+: ${posixTools}/bin/bash    (bash 2.05b, built from TCC in stage 4)
```

### Compiling kaem from source in stage 0

Instead of downloading the pre-compiled kaem-optional-seed (618 bytes), we
compile kaem from auditable hex0 source. This reduces the root of trust to
a single 229-byte binary (hex0):

```nix
# In stage0-seeds.nix:
kaem = builtins.derivation {
  name = "kaem";
  inherit system;
  builder = "${hex0}";          # hex0 IS the compiler
  args = [ "${kaemHex0Src}" "${placeholder "out"}" ];
  # hex0 reads hex pairs from input file, writes binary to output file
};
```

Where `kaemHex0Src` is fetched from `stage0-posix-x86/kaem-minimal.hex0`
(same repo/version used for all stage0-posix sources). The hex0 binary
reads hex pairs from the source file and writes the compiled ELF to $out.

This means kaem is built from source, not downloaded as an opaque binary.
The ONLY opaque binary in the entire chain is hex0 (229 bytes).

No `/bin/sh` is ever used anywhere in the bootstrap chain.

## Environment Variable Handling

The central challenge is that `$out` and `$TMPDIR` are only known at build
time (set by the Nix daemon). Different builders handle this differently:

| Builder | How it gets $out/$TMPDIR |
|---------|------------------------|
| `/bin/sh` | Shell expands `$out`, `$TMPDIR` naturally |
| `builtin:fetchurl` | Nix daemon handles internally |
| kaem (full) | Expands `${out}` and `${TMPDIR}` from environment |
| kaem-seed | **Cannot** — no variable expansion |
| hex0 nix-kaem | Would need env var reading via syscalls |
| bash 2.05b | Full POSIX variable expansion |

The full kaem (built in stage 1) DOES support `${out}` and `${TMPDIR}`
expansion, so stages 2-3 are covered. Stage 1 is the only problem.

## Concrete Implementation: Stage 2 as kaem Script

Example of how stage 2 would look with kaem as builder:

```nix
builder = "${mescc-tools}/bin/kaem";
args = [ "--verbose" "--strict" "--file" script ];
```

Where `script = builtins.toFile "build-mes.kaem" ''...''` contains:

```kaem
# Stage 2: Build GNU Mes
# All paths pre-interpolated by Nix at eval time

cd ${TMPDIR}
${mescc-tools}/bin/mkdir ${TMPDIR}/build
cd ${TMPDIR}/build

# Extract sources
${mescc-tools}/bin/ungz --file ${mesSrc} --output ${TMPDIR}/build/mes.tar
${mescc-tools}/bin/untar --file ${TMPDIR}/build/mes.tar

# ... (all commands enumerated explicitly)

# Create config.h (pre-baked as builtins.toFile, copied in)
${mescc-tools}/bin/cp ${configH} ${TMPDIR}/build/mes-0.27.1/include/mes/config.h

# Compile mes-m2
M2-Planet --debug --architecture x86 ...all 80+ file arguments...
```

Note: `${TMPDIR}` and `${out}` here are kaem variable expansions (at build
time), while `${mescc-tools}`, `${mesSrc}`, etc. are Nix interpolations
(at eval time). The kaem `${VAR}` syntax conveniently matches Nix's, but
in `builtins.toFile` strings, Nix interpolation happens first, and any
remaining `${...}` patterns must use `''${...}` to escape Nix and be passed
through as literal text for kaem.

In Nix:
```nix
script = builtins.toFile "build.kaem" ''
  cd ''${TMPDIR}
  ${mescc-tools}/bin/mkdir ''${out}
  ${mescc-tools}/bin/mkdir ''${out}/bin
'';
```

## What kaem Cannot Do (and Workarounds)

| Shell Feature | Workaround for kaem |
|--------------|-------------------|
| `for f in ...; do ... done` | Enumerate all commands explicitly |
| `mkdir -p a/b/c` | Chain: `mkdir a`, `mkdir a/b`, `mkdir a/b/c` |
| `chmod -R u+w .` | Use mescc-tools-extra chmod per file, or accept |
| `cat > file << 'EOF'` | Use `builtins.toFile` + `cp` |
| `find . -name ...` | Not needed if paths are known at eval time |
| `sed -i 's/...'` | Use mescc-tools `replace` or `simple-patch` |
| Functions | Inline or use separate kaem subscript files |
| `tar xzf` | `ungz` + `untar` (mescc-tools) |
| `2>/dev/null` | Remove or accept error output |
| `cmd || true` | Use `if` to check exit status |
| `$(nproc)` | Hardcode or omit `-j` flag |

## Appendix A: Stage File Changes Summary

| Stage | Current Builder | New Builder | Complexity |
|-------|----------------|-------------|------------|
| 0 | builtin:fetchurl | builtin:fetchurl (unchanged) | None |
| 1 | /bin/sh | seeds.kaem (kaem-seed, 618 B) | Medium (two-phase: kaem-seed builds, full kaem installs) |
| 2 | /bin/sh | mescc-tools kaem | High (refactor script to kaem format) |
| 3 | /bin/sh | mescc-tools kaem | High (refactor script to kaem format) |
| posix | /bin/sh | mescc-tools kaem | Medium (simple compile-and-link) |
| 5-17 | /bin/sh | posixTools bash | Low (change builder path) |

The hardest work is stages 2-3, which require converting complex shell
scripts to kaem-compatible format. Stages 5-17 are trivial — just change
the builder path from `/bin/sh` to `${posixTools}/bin/bash`.

## Appendix C: Nix Sandbox /bin/sh Semantics

For context, Nix's `/bin/sh` in the sandbox is:
- On Linux: A statically-linked dash or bash from the Nix store, bind-mounted
  to `/bin/sh` inside the sandbox
- It is NOT the host's `/bin/sh`
- It is deterministic — same binary for all builds on the same Nix version
- The Nix manual documents this as part of the build contract

Some projects (like Guix) consider this acceptable. The purist position
(which AOS takes) is that even this Nix-provided shell should be eliminated
in favor of tools built from the bootstrap seeds.
