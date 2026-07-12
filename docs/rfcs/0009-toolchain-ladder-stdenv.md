# RFC-0009: A coherent toolchain-ladder stdenv — per-tier mini-stdenv, manifest-driven packages, stock `make bootstrap`

- **Status:** Implemented — Phases 0-5 complete
- **Date:** 2026-06-15
- **PR:** _(to be filled)_
- **Audience:** anyone working on `stdenv/` — the bootstrap chain
  (`stdenv/bootstrap/`), the GCC version ladder
  (`stdenv/toolchains/`), or the build machinery (`stdenv/phases.nix`,
  `stdenv/cc-wrapper.nix`, `lib/derivations.nix`).

## Problem

The toolchain ladder works — `nix-build -A stdenv` produces a GCC 14.3.0
stdenv from a hex0 seed, green end-to-end. But it was grown tier by tier,
and the result is ~22,400 lines across ~250 near-identical hand-rolled
package files that ignore the build machinery the rest of the repo
already uses.

### Two layers, very different in character

| Layer | Span | LOC | Character |
| --- | --- | --- | --- |
| `stdenv/bootstrap/` | hex0 → GCC 2.95.3 (stage0–stage5) | ~7,500 | Genuinely bespoke: kaem/MesCC/TinyCC, MesCC-libc quirks, autoconf-2.5x-with-broken-sed workarounds. **Must stay custom.** |
| `stdenv/toolchains/` | GCC 3.4.6 → 14.3.0 (10 tiers) | ~22,400 | ~90% duplicated. Each package a raw `builtins.derivation` reimplementing unpack, autotools-timestamp handling, `PATH`, and `CFLAGS` by hand. **This is the target of this RFC.** |

### The duplication, concretely

Every one of the ~250 toolchain package files
(`stdenv/toolchains/<tier>/<pkg>.nix`) is a raw `builtins.derivation`
that hand-writes the same five things. From
`stdenv/toolchains/gcc8/coreutils.nix` and
`stdenv/toolchains/gcc14/coreutils.nix` — which differ only in version,
hash, the `8.5.0` include-path string, and two configure flags:

1. **A tar-pipe unpack** to dodge the coreutils `fchmodat` ENOSYS bug:
   `mkdir X && (cd $src && tar cf - .) | (cd X && tar xf -)`.
2. **A three-pass timestamp dance** to stop autotools regenerating:
   `find … -name '*.y' … touch; sleep 1; find … -name '*.c' … touch;
   sleep 1; find … configure Makefile.in … touch`.
3. **An inline 20-entry `PATH` string**:
   `PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:…"` — retyped,
   in full, in every file.
4. **Hand-written compiler flags** that manually reimplement a
   cc-wrapper: `CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem
   $GCC_INCDIR-fixed -isystem ${glibc}/include"`,
   `LDFLAGS="-L${glibc}/lib -static"`.
5. **The actual build**: `configure --build/--host/--target … && make &&
   make install`.

Points 1–4 are pure boilerplate. Point 5 — the only part that should
exist — is buried under them.

### The irony

The repo **already has** the machinery to make point 5 the *whole* file:

- `stdenv/phases.nix:147` — `autoconfPhases`, stock
  `./configure --prefix=$out $configureFlags && make && make install`,
  plus a shared `unpackPhase` (`phases.nix:13`) and `fixupPhase`
  (`phases.nix:45`).
- `stdenv/cc-wrapper.nix` — already parametrized over `cc` / `libc` /
  `binutils_` / `coreutils`, and already supports turning hardening off
  via `defaultHardening = ""`. It injects `-isystem`, `-B`, `-L`,
  `-rpath`, and `-dynamic-linker` so packages never write point 4 by
  hand.
- `lib.mkDerivation` (`lib/derivations.nix`) — drives phases, `PATH`
  from `buildDeps`, and `$out` plumbing.

The production package set (`pkgs/`) uses all three. The toolchain
ladder predates them and reimplements them, badly, 250 times.

### Why it wasn't *just* done with the global stdenv

The global stdenv's `mkDerivation` (`stdenv/default.nix:46`,
`mkStdenvFromTier`) closes over the **final** tier (GCC 14). It cannot
build GCC 14 — chicken-and-egg. Each tier is built by its **predecessor**,
so there is no single global stdenv to reuse for the ladder.

That argues for reusing the *machinery* parametrized per tier — **not**
for hand-rolling every package. `mkStdenvFromTier` already proves the
wrapping is mechanical; it is simply applied to one tier instead of all
of them.

## Design

Four moves, plus a ladder principle. The first three remove the
boilerplate (points 1–4 above); the fourth collapses the per-tier
divergence in the two genuinely-hard packages; the principle settles
how aggressively each tier self-hosts.

### 1. A per-tier mini-stdenv: `mkTierStdenv`

Generalize `mkStdenvFromTier` (`stdenv/default.nix:46`) so it can wrap
**any** tier, not just the latest. Given a tier's just-built components
`{ gcc, binutils, glibc, coreutils, bash, … }` it returns a
`mkDerivation` that drives `autoconfPhases` with that tier's cc-wrapper
and `initialPath`.

```text
mkTierStdenv :: { gcc, binutils, glibc, coreutils, … ; prev ; platform }
             -> { mkDerivation, cc, initialPath }
```

The global `mkStdenvFromTier` becomes a thin call to `mkTierStdenv` on
the final tier — the two stop being separate concepts.

### 2. One cc-wrapper per tier

`cc-wrapper.nix` already takes everything needed (`cc`, `libc`,
`binutils_`, `coreutils`, `hostPlatform`, `defaultHardening`). Build one
wrapper per tier from that tier's compiler+libc+binutils. This **deletes
points 3 and 4** from every package: the wrapper owns the include/lib
search paths and the `PATH`-resident toolchain.

Tier tools link `-static -no-pie` and want no hardening, so tiers
instantiate the wrapper in a **static profile**:

- `defaultHardening = ""` (the wrapper already treats empty as "disable
  everything", `cc-wrapper.nix:11–13`);
- a `staticDefault = true` knob that bakes in `-static -no-pie` and skips
  the dynamic-linker / rpath injection.

This is the one small extension cc-wrapper needs; everything else it does
today.

### 3. Quirks become shared, flagged phase behavior

The tar-pipe unpack and the autotools-timestamp dance move into
`unpackPhase`/a small `freezeAutotoolsTimestamps` helper, gated by flags,
set **once per tier** where the bug actually bites — not copy-pasted 250
times:

- `unpackMode = "tar-pipe"` — for tiers whose `prev.coreutils` carries
  the `fchmodat`/`cp -r` ENOSYS bug (the gcc8+ era,
  per `MEMORY.md`). Newer tiers can use the stock `cp -r` unpack.
- `freezeAutotoolsTimestamps = true` — runs the
  `touch`-inputs-then-outputs sequence, with `AUTOCONF/AUTOHEADER/
  ACLOCAL/AUTOMAKE=true` and `MAKEINFO` exported, so autotools never
  regenerate. This is a single helper, parametrized, not an inline
  `find` triplet per file.

These belong to `stdenv/phases.nix` next to `unpackPhase`/`fixupPhase`,
where every consumer already looks.

### 4. POSIX tools as data; `mkGcc`/`mkGlibc` as shared builders

**POSIX/autotools tools become a manifest.** The ~20 mechanical tools per
tier (coreutils, bash, sed, grep, gawk, gnumake, findutils, diffutils,
tar, gzip, patch, m4, flex, bison, autoconf, automake, perl, texinfo,
help2man, gperf, python3) collapse to a per-tier table consumed by one
shared `mkAutotoolsTool` recipe:

```text
# stdenv/toolchains/<tier>/manifest.nix  (illustrative)
{
  coreutils = {
    version = "9.5";
    url     = "https://mirrors.kernel.org/gnu/coreutils/coreutils-9.5.tar.xz";
    hash    = "sha256-…";
    configureFlags = [ "--disable-nls" "--enable-no-install-program=stdbuf"
                       "--enable-single-binary=symlinks" ];
  };
  sed = { version = "4.9"; url = "…"; hash = "…";
          configureFlags = [ "--disable-nls" ]; };
  # …
}
```

A ~90-line file becomes a ~5-line record. `mkAutotoolsTool` =
`tierStdenv.mkDerivation { phases = autoconfPhases {}; … }` + the manifest
fields. Per-tier patches attach as an optional `patches` list; genuine
one-offs (the bash `psize.sh` hang, a K&R fix) attach as an optional
`preConfigure`/`postPatch` snippet on that one record — the exception
stays local instead of contaminating the template.

**`gcc` and `glibc` unify into shared parametrized builders**
(`stdenv/toolchains/lib/gcc.nix`, `…/glibc.nix`), per the decision to go
aggressive here. There are only ~6 GCC tiers; today they are ~6 fully
divergent 150–360-line files (`gcc4_8/gcc.nix` is 362 lines) that share
the same skeleton. `mkGcc` takes:

```text
mkGcc {
  version; src; inTreeDeps = { gmp; mpfr; mpc; isl; };
  languages = [ "c" "c++" ];
  configureFlags;            # tier-specific (--enable-default-pie, …)
  patches;                   # the GCC-14 limits.h fixup, pointer-cmp, …
  bootstrap = false;         # see ladder principle below
  prev; platform;
}
```

The legitimately version-specific logic stays — in-tree GMP/MPFR/MPC/ISL,
the target sysroot, the specs-file scrubbing that keeps `prev.glibc`'s
hash out of the runtime closure (`gcc14/gcc.nix:178–214`), the
`include-fixed/limits.h` chain (`gcc14/gcc.nix:120–140`) — but it lives in
**one** builder with a per-tier quirk table, not copy-pasted six ways.
`mkGlibc` follows the same shape (version, patches, `--enable-cet` toggle,
the `make -k install PERL=true` and `rm -rf libidn` workarounds from
`MEMORY.md`).

The cross tiers (`*_cross`) keep their explicit multi-stage sequence
(binutils → stage1 gcc → headers → glibc → stage2 gcc → Canadian cross,
`gcc8_cross/default.nix:9–18`) but assemble it from the **same**
`mkGcc`/`mkGlibc`/`mkAutotoolsTool` pieces — the sequence is the only
thing that stays bespoke, and it's genuinely structural.

### The ladder principle: self-host only where it pays

"Recompile each tier with itself for speed" is the wrong default. Two
facts settle it:

- **The code a GCC emits is fixed by its source, not by what compiled
  it.** GCC-14 built by GCC-11 emits byte-identical code to GCC-14 built
  by GCC-14.
- **Only the speed of the gcc *binary* depends on who compiled it.** A
  self-built gcc-N is a faster executable; its *output* is unchanged.

So self-recompiling buys a faster compiler, never better/different
artifacts. That makes it a pure wall-clock tradeoff:

**Intermediate tiers (gcc3_4 … gcc11): single-pass, `--disable-bootstrap`.**
Each exists only to build its successor, then is discarded. Self-recompiling
costs a full extra gcc build (the slowest package in the tier) to speed up
one disposable tool. It doesn't pay. Integrity is checked transitively: a
miscompiled gcc-N fails to build gcc-(N+1) or fails its testsuite. This is
what the tree does today and it is correct.

**Final tier (gcc14): full stock `make bootstrap`.** GCC 14 is the default
compiler for the entire OS — hundreds of builds forever — so a faster
binary amortizes over everything. GCC's own Makefile already does the
right thing:

```text
stage1:  gcc-14 built by gcc-11            (just needs to work)
stage2:  gcc-14 built by stage1
stage3:  gcc-14 built by stage2            ← optimized; this is what ships
         stage2 vs stage3 compared bit-for-bit  ← free reproducibility proof
```

This is **more** stock than the tree today, which passes
`--disable-bootstrap` (`gcc14/gcc.nix:105`) and carries a *disabled*
manual self-recompile TODO blocked on an in-tree-GMP `CC_FOR_BUILD` issue
(`toolchains/default.nix:140–143`). Stock `make bootstrap` *is* the
self-recompile done correctly — it is precisely the GMP/host-compiler
interplay the hand-rolled glue got wrong — so adopting it **deletes**
custom code, matching the "use the compiler's own makefiles" goal.

**Bootstrap gcc only — do not rebuild the whole final tier.** binutils,
glibc, and the POSIX tools emit byte-identical output whether compiled by
stage1-gcc14 or stage3-gcc14 (same compiler *version*, same codegen). Only
gcc benefits from bootstrapping. So on the final tier: `make bootstrap`
for **gcc**, then build the rest **once** with the resulting stage3 gcc.
The old "recompile the latest tier with itself" TODO was overkill if it
meant rebuilding everything.

Encoded as the `mkGcc { bootstrap = …; }` knob: `false` on every
intermediate tier, `true` on the final/default tier.

## Migration plan

Phased, lowest-risk-first; the ladder stays green at every step because
each migrated package produces a store path that must still build under
its successor.

- [x] **Phase 0 — machinery. Implemented.** Add `mkTierStdenv`, the cc-wrapper static
  profile, and the `unpackMode`/`freezeAutotoolsTimestamps` phase flags.
  No package changes yet; refactor `mkStdenvFromTier` to call
  `mkTierStdenv`. Verify `nix-build -A stdenv` is byte-identical (`.drv`
  diff) to before. Verified for Phase 0: the final `aos-cc-wrapper.drv`
  and `aos-stdenv.drv` paths match the pre-change baseline, remote
  `checks.eval` passes, the stdenv wrapper builds, and adversarial review
  findings were addressed.
- [x] **Phase 1 — POSIX tools, one tier. Implemented.** Converted gcc8's
  POSIX/autotools tools to `mkAutotoolsTool` + `manifest.nix`. Verified
  for Phase 1: the migrated tool output paths changed, as expected from
  changing the derivation recipe, but all 21 migrated outputs keep
  identical file lists versus the Phase 0 baseline; the refactored
  `stdenv` builds; remote `checks.eval` passes; the Phase 1 Nix files
  pass Alejandra; and adversarial review findings were addressed.
- [x] **Phase 2 — POSIX tools, all tiers. Implemented.** Rolled the manifest
  conversion across the remaining native tiers, including `python3` ownership
  for gcc11 and gcc14. Verified for Phase 2: touched Nix files parse locally;
  no native tier default routes `python3` through `prev.python3`; direct
  remote builds of `[ gcc11.python3 gcc14.python3 ]` succeeded on an
  x86_64-linux builder; both resulting Python interpreters start without
  prefix warnings, import the required built-in modules, expose working
  `sysconfig` and `distutils.sysconfig` metadata, and ship config scripts with
  AOS bash shebangs; and adversarial review found no serious ownership or
  install-layout issues.
- [x] **Phase 3 — `mkGlibc`. Implemented.** Unified glibc across tiers; it is
  lower-variance than gcc. Verified for Phase 3: touched Nix files parse
  locally; strict evaluation exposes the expected glibc names and gcc14 split
  outputs; corrected remote builds of `[ gcc8.glibc gcc11.glibc gcc14.glibc ]`
  succeeded on an x86_64-linux builder; the corrected logs show gcc8's
  `CFLAGS` reaching configure and gcc14 using its `$TMPDIR/ccwrap/gcc` wrapper;
  remote smoke checks confirm the glibc loaders/libraries and gcc14
  bin/dev/static/getent output split; and adversarial review caught and verified
  the configure-environment splice fix.
- [x] **Phase 4 — `mkGcc`. Implemented.** Unified native gcc tiers behind
  `mkGcc`; switched the final tier to `bootstrap = true` (stock
  `make bootstrap`) and retired the disabled self-recompile TODO. Verified for
  Phase 4: touched Nix files parse locally; remote `stdenv.gccStage2` builds
  successfully on an x86_64-linux builder; raw unwrapped GCC 14 C and C++
  smoke tests compile and run without caller-supplied linker flags; installed
  specs contain this-tier glibc headers, glibc shared/static library paths,
  rpath/rpath-link, and the glibc dynamic linker; binutils symlinks point at
  this tier's binutils; the final GCC closure has no `glibc-2.34`,
  `gcc-11.5`, or `binutils-2.37`; a direct `gcc4_8.gcc` build resolves on the
  same builder; and adversarial review found no blocking issues.
- [x] **Phase 5 — cleanup. Implemented.** Added a shared manifest-toolset
  helper and removed the repeated per-tier `default.nix`
  `mkAutotoolsTool manifest.<name>` assignments where the manifest already
  owns the package details. Verified for Phase 5: touched Nix files parse
  locally; strict eval forces representative manifest-built attrs across every
  native tier; remote builds of `stdenv.gccStage2`, `stdenv.bash`, and an
  early `gcc3_4.patch` manifest tool resolve successfully on an x86_64-linux
  builder; and adversarial review found no blocking issues.

Each phase is independently revertible and CI-gated on `nix-build -A
stdenv` plus the existing eval/VM checks.

## What stays custom (and why)

- **All of `stdenv/bootstrap/`.** hex0 → GCC 2.95.3 and the
  stage4/stage5 MesCC/TinyCC/autoconf-2.5x workarounds
  (`stdenv/bootstrap/lib.nix`) are irreducibly bespoke. Untouched.
  Keep stage5 glibc fail-closed at the compiler ABI boundary: `make -k` may
  pass optional static-bootstrap program failures, but the producer must
  verify and install `libc.a`, `crt1.o`, `crti.o`, and `crtn.o` before it
  succeeds. Honor `NIX_BUILD_CORES` for the build because glibc is the longest
  bootstrap frontier and its make graph is parallel-safe after the generated
  ordering inputs are pinned. Do not require `big-parallel`: the 2026-07-12
  validation reserved a whole builder but the glibc 2.2.5 make graph used
  only 1.2–1.3 cores, so reserving that capacity reduces graph-level fan-out
  without shortening this frontier. Do not defer ABI validation to the
  downstream GCC build because it hides the actual glibc failure and admits an
  unusable libc store path.
- **Bootstrap POSIX outputs.** Treat the exported stage5 tools as compiler
  inputs, not best-effort conveniences. In particular, stage5 findutils must
  verify executable `bin/find` and `bin/xargs` before publishing its output;
  every later GCC tier puts that output on `PATH`, and admitting a partial
  object turns the missing utility into misleading `GCC_NO_EXECUTABLES`
  failures deep inside fixincludes and target-library configure scripts.
  Expose glibc's stable `FNM_CASEFOLD` flag bit directly for findutils 4.1's
  `-iname`/`-ipath` implementation; enabling all GNU declarations instead
  conflicts with the package's legacy `basename` declaration. Its recursive
  Makefile can mask the failed `find` subdirectory behind later successful
  subdirectories, which is why the executable validation remains mandatory.
- **`mkGcc`/`mkGlibc` internals.** Shared builders, but the
  version-specific quirks (in-tree GMP, sysroot, specs scrubbing,
  `limits.h` chain, glibc install workarounds) remain — stock autotools
  defaults genuinely don't apply to a cross-built libc or an
  in-tree-GMP compiler. GCC 3.4's target-library link flags must carry
  `-B<previous-glibc>/lib` as well as `-L`: `-L` locates `libc.a`, while the
  in-tree `xgcc` resolves `crt1.o`, `crti.o`, and `crtn.o` through compiler
  prefixes before the new compiler has an installed start-file directory.
  Build and install the C-only GCC 3.4 tier through `all-gcc` and
  `install-gcc`: the full GCC 3.4 source archive's default top-level target
  also enters `libstdc++`, Boehm GC, and libffi despite
  `--enable-languages=c`, exposing target runtimes that this tier does not
  promise and that are incompatible with its bootstrap kernel headers.
  Keep the matching native glibc 2.3.4 static-only, as the neighboring
  cross-glibc and glibc 2.5 bootstrap tiers already are. Its consumers link
  with `-static`; building the unconsumed dynamic loader enters glibc's
  `rtld-Rules` path before the old make graph has produced every subdirectory
  stamp and does not expand the compiler ABI this tier promises. Remove the
  versioned i386 `vm86` routine from that static build, because glibc only
  generates its object rule when shared libraries are enabled; retaining the
  routine leaves `misc/stamp.o` with an impossible `vm86.o` prerequisite.
- **Cross-tier sequencing.** The multi-stage cross dance stays explicit;
  only its building blocks are shared.

## Expected outcome

The ~22,400 toolchain LOC should drop by well over half: the POSIX-tools
layer becomes per-tier manifests, each quirk lives in exactly one place,
`gcc`/`glibc` collapse from ~12 divergent files into two parametrized
builders, and the ladder builds with stock `autoconfPhases` + a real
cc-wrapper instead of hand-written `-nostdinc -isystem` strings — the
"mostly stock" target. The final compiler ships as a stock
`make bootstrap` stage3 binary with a free reproducibility check, and the
disabled self-recompile TODO is deleted rather than fixed.

## Open questions / decisions

1. **Manifest granularity.** One `manifest.nix` per tier (chosen above),
   or a single cross-tier table keyed `pname → { perTier overrides }`?
   Per-tier files keep diffs local and match the existing directory
   layout; a single table maximizes dedup but couples tiers. _Leaning
   per-tier._
2. **`mkGcc` aggressiveness on the cross tiers.** Fold the cross stage1/
   stage2 gcc into `mkGcc` flags, or keep a separate `mkCrossGcc`? The
   Canadian-cross step is different enough that a thin `mkCrossGcc`
   wrapper over `mkGcc` may read better than a mega-flagged single
   builder.
3. **`make bootstrap` on the final tier vs. every tier.** This RFC
   recommends final-tier-only. A correctness-paranoid alternative runs
   `make bootstrap` on every tier (~3× ladder build time) to get the
   stage2==stage3 fixpoint check at each rung. _Recommend final-tier-only;
   flagged here for explicit sign-off._
