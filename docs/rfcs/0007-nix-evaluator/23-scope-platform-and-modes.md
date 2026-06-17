# RFC-0007 - Scope, platform, and language modes

Every other document in this RFC set argues about *how* aos-nix evaluates Nix
fast and byte-identically. This document draws the box around *what* it
evaluates, *on which machines*, and *under which evaluation modes*. The
compatibility contract in
[compatibility constraints](02-compatibility-constraints.md) says aos-nix must
produce the byte-identical `.drv` C++ Nix produces *for the inputs it handles*;
this document fixes the set of inputs, host architectures, and evaluation flags
over which that "for the inputs it handles" quantifier ranges. The integration
seam in [integration with AOS](14-integration-with-aos.md) turns everything
outside that box into a transparent `NixCli` fallback.

Four decisions are made here, each stated as a decision with rationale:

1. **Flakes are out of scope** — aos-nix targets non-flake evaluation of the
   AOS package set and `systems/` variants.
2. **Restricted / pure-eval modes and allowed-paths are in scope** — because
   they change observable behavior for the *same* flags, parity demands them.
3. **Multi-arch portability is in scope with a critical invariant** — host
   architecture affects eval *speed*, never eval *output*.
4. **`nixVersion` / `langVersion` spoofing is a parity requirement** — version
   gates must take identical branches or the `.drv` diverges.

The unifying principle: a decision belongs in this document when getting the
*scope* wrong would either inflate the parity surface beyond what the harness
can prove (flakes) or silently violate parity inside the surface we keep
(modes, arch, version reporting).

---

## 1. Flakes are out of scope

> **Decision.** aos-nix targets **non-flake** evaluation: the AOS package set
> (`default.nix` plus its attribute tree) and the `systems/` variants
> (`lib.evalModules`-composed configurations). The flake-specific builtins —
> `builtins.getFlake`, `builtins.parseFlakeRef`, `builtins.flakeRefToString` —
> are **unsupported and stubbed**. Any evaluation that reaches a flake builtin
> returns a typed `Unsupported` error and falls back to `NixCli`
> ([integration with AOS](14-integration-with-aos.md) §6.1). Flake evaluation,
> if it is ever needed, is a **separate future workstream**, not a corner of
> this one.

### 1.1 Why AOS does not need flakes on the eval hot path

AOS is, by construction, a non-flake repository. As recorded in
[CLAUDE.md](../../../CLAUDE.md), the package set is a plain Nix expression tree
rooted at `default.nix`, and system variants are assembled by `lib.evalModules`
under `systems/` — the classic `nix-instantiate -f <file> -A <attr>` model, not
`nix build .#<output>`. The `aos` CLI's existing seam confirms this:
`NixCli::instantiate` shells out to `nix-instantiate -f <file> -A <attr>` (see
[integration with AOS](14-integration-with-aos.md) §2), exactly the non-flake
instantiation path. The repeated evaluation cost that motivated this RFC
([motivation and goals](01-motivation-and-goals.md)) lives entirely in that
path; flakes are not on the hot loop we are optimizing.

### 1.2 Why flakes are a deliberately excluded *large surface*

Flakes are not "a few more builtins." They are a parallel evaluation
subsystem with its own schema, file formats, reference grammar, and cache:

- [ ] **The `flake.nix` schema** — a constrained top-level attrset
      (`inputs`, `outputs`, `nixConfig`) with its own well-formedness rules and
      `outputs` function-application protocol.
- [ ] **Lock files** — `flake.lock`, a JSON graph of pinned, content-addressed
      input nodes with its own node-deduplication and `follows` resolution
      semantics that feed directly into store-path identity.
- [ ] **Flake references** — the `flakeref` grammar (`github:owner/repo/ref`,
      `git+https://…`, `path:…`, indirect registry refs) parsed by
      `parseFlakeRef` and re-serialized by `flakeRefToString`, plus the
      flake *registry* indirection layer.
- [ ] **The flake eval cache** — Nix's on-disk evaluation cache keyed by locked
      flake refs, a second caching system entirely distinct from the in-process
      incremental cache in
      [incremental evaluation cache](12-incremental-evaluation-cache.md).
- [ ] **`getFlake` impurity rules** — `builtins.getFlake` requires the flake
      reference to be *locked* (contain a Git revision or content hash) unless
      `--impure` is set, tying it to fetcher and lock-file semantics that the
      non-flake path never touches.

Each is its own parity obligation: the lock-file graph and flakeref
normalization both influence which store paths are realized, so a
flake-supporting aos-nix would have to reproduce `flake.lock` resolution and
flakeref canonicalization byte-for-byte — a surface as large as the one this RFC
already commits to, with no AOS workload to justify it. Excluding flakes is not a
corner cut; it keeps the parity surface honest. We do not add an *input class* we
cannot prove byte-identical across the AOS closure, and there is no AOS flake
closure to prove it against.

### 1.3 How the boundary is enforced

The three flake builtins are present in the builtin table
([primops and runtime ABI](10-primops-and-runtime-abi.md)) only as stubs that
raise `NativeEvalError::Unsupported { feature: "flakes", .. }`. Per the failure
model in [integration with AOS](14-integration-with-aos.md) §6.1, `Unsupported`
triggers a *transparent* top-level fallback to `NixCli`, so even a stray flake
expression yields a correct `.drv` — via the subprocess oracle, not natively.
The differential harness
([differential testing](15-differential-testing-and-benchmarking.md)) needs no
flake fixtures because the AOS closure contains none; if a future AOS component
grows a flake entry point, the harness sees the fallback counter increment
rather than a divergence, which is the safe failure mode.

> **Boundary, stated plainly.** aos-nix evaluates the AOS non-flake package set
> and `systems/` variants. Flakes fall back to `NixCli`. There is no partial
> flake support: it is all-fallback until and unless a dedicated future
> workstream takes it on, at which point it gets its own scope document and its
> own gate.

---

## 2. Restricted and pure-eval modes, and allowed-paths

> **Decision.** aos-nix implements `--pure-eval` semantics and the
> `restrict-eval` / `allowed-paths` / `allowed-uris` access controls to
> **match the pinned C++ Nix exactly**. These modes are *in scope* because they
> are observable: the same expression under the same flags must take the same
> branches and reach (or refuse) the same eval-time I/O on aos-nix as on C++
> Nix, or the resulting `.drv` (or the resulting *error*) diverges.

This decision has two faces. One is pure *parity*: the modes change behavior,
so behavior must match. The other is the *eval-time I/O boundary*: these modes
are precisely the policy layer that mediates `readFile` / `import` / fetchers,
and that boundary ties directly into the fiber/tokio I/O model of
[parallel evaluation](13-parallel-evaluation.md) §5.5 and the impure-read cache
keying of [incremental evaluation cache](12-incremental-evaluation-cache.md).

### 2.1 What `--pure-eval` must do, verified against the manual

In pure evaluation mode, C++ Nix restricts file-system and network access to
content addressed by cryptographic hash, so that the evaluation result is
*completely reproducible from the command-line arguments*. Concretely, matching
the manual's enumeration:

- [ ] **`builtins.currentTime`** is unavailable / throws — it is impure by
      definition (wall-clock).
- [ ] **`builtins.currentSystem`** is **not available in pure evaluation mode**
      (the manual states `currentSystem` is "Not available in pure evaluation
      mode"); same for `builtins.storePath`.
- [ ] **`builtins.getEnv`** must not read the ambient process environment
      (environment access is an impurity).
- [ ] **`exec`** and other impure escape hatches are disabled.
- [ ] **`$NIX_PATH` and `-I` are ignored**; impure path resolution is off.
- [ ] **Fetchers require pinning** — `fetchGit`/`fetchMercurial` require a
      revision, `fetchurl`/`fetchTarball` require a `sha256`; and no file-system
      access is permitted outside the paths returned by the fetchers.

aos-nix must reproduce each of these *as a behavior*, not merely as a flag it
accepts. If C++ Nix throws on `builtins.currentSystem` under `--pure-eval` and
aos-nix returns `"x86_64-linux"`, then an expression that branches on
`builtins.tryEval (builtins.currentSystem)` takes a different branch and emits a
different `.drv` — a parity break that the harness
([differential testing](15-differential-testing-and-benchmarking.md)) catches
as either a `.drv` byte diff or an error-outcome mismatch (both are gate
failures per [compatibility constraints](02-compatibility-constraints.md) §7).

### 2.2 What `restrict-eval` / allowed-paths / allowed-uris must do

`restrict-eval`, when true, forbids the evaluator from accessing any files
outside the Nix search path (as set via `$NIX_PATH` / `-I`) or any URIs outside
`allowed-uris`. `allowed-uris` is the allow-list of URI prefixes
(`github:`, `https://…`, etc.) that restricted evaluation may reach.
aos-nix mediates the same three eval-time operations through the same policy:

| Eval-time operation | Policy gate it must honor |
|---|---|
| `builtins.readFile` / path coercion (`./x`) | allowed-paths / search-path roots |
| `import <path>` | allowed-paths / search-path roots |
| `fetchurl` / `fetchTarball` / `fetchGit` | allowed-uris (and pure-eval pinning) |

The decision is to *match*, not to *innovate*: aos-nix's allowed-path check must
admit and refuse exactly the paths C++ Nix admits and refuses for the same
configuration. The error-class parity bar from
[compatibility constraints](02-compatibility-constraints.md) §8 applies — an
access that C++ Nix rejects "in pure eval mode (use `--impure` to override)"
must be rejected by aos-nix too, since some expressions guard on `tryEval` of a
forbidden read.

### 2.3 Why this is the eval-time I/O boundary, not a side feature

These modes are not an afterthought layered on top of evaluation; they *are*
the evaluator's I/O boundary. Two cross-cutting consequences:

- [ ] **Fiber/tokio mediation
      ([parallel evaluation](13-parallel-evaluation.md) §5.5).** Eval-time reads
      and fetches are the only I/O the evaluator performs, and they are exactly
      what the fiber scheduler suspends on. The allowed-paths/allowed-uris check
      is the natural choke point through which every such suspension passes, so
      the policy enforcement and the async I/O model share one gate. A read that
      pure-eval forbids must be refused *before* it ever becomes an awaited I/O
      future.
- [ ] **Impure-read cache keying
      ([incremental evaluation cache](12-incremental-evaluation-cache.md)).** The
      early-cutoff cache is sound only because Nix is pure; any *permitted*
      impure read (a `readFile` of an allowed path, a fetched fixed-output) must
      be folded into the cache key, or a cached result could outlive the input
      it depended on. `--pure-eval` shrinks the set of admissible impure reads to
      content-addressed ones, which is exactly the set the cache can key on
      safely. The mode and the cache-keying policy are therefore co-designed: the
      stricter the mode, the more of the cache key is content-addressed and the
      stronger the early-cutoff guarantee.

Supporting these modes is not optional polish — it is implementing the
evaluator's only legitimate interface to the outside world, with the *same*
admit/refuse decisions C++ Nix makes, so that both the `.drv` output and the
cache that accelerates it stay sound.

---

## 3. Multi-arch portability and the host-independence invariant

> **Decision.** aos-nix supports **64-bit x86-64 and aarch64 hosts** — the two
> AOS target architectures — and nothing else; **32-bit is unsupported**. The
> value representation
> ([value representation](05-value-representation.md)) and the Cranelift
> backend ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md))
> both target both arches.
>
> **Critical invariant.** Host architecture affects evaluation *speed*
> (codegen), **never** evaluation *output*. For a given
> `builtins.currentSystem`, the **same `.drv` must be produced on an x86-64 host
> and on an aarch64 host**. The differential harness
> ([differential testing](15-differential-testing-and-benchmarking.md)) must
> confirm cross-host `.drv` identity.

### 3.1 Why the value representation constrains the host word size

The optimized value layout in
[value representation](05-value-representation.md) is a NaN-boxed / tagged value
that uses **pointer tagging** — it stuffs type tags into the spare bits of a
pointer and into the unused payload bits of an IEEE-754 double's NaN space. That
trick is only sound under three assumptions, all of which hold on x86-64 and
aarch64 (the AOS targets) and none of which hold on a 32-bit host:

- [ ] **64-bit words** — the NaN-boxing scheme needs a 64-bit slot to overlay a
      `double` and a tagged pointer in the same machine word.
- [ ] **8-byte-aligned heap objects** — tagging the low pointer bits requires
      that heap allocations are 8-byte aligned, so the low 3 bits are reliably
      zero and free to carry a tag.
- [ ] **Canonical (non-sign-extended-beyond-48-bit) addresses** — the high
      pointer bits used by the NaN-box must be predictable; x86-64 and aarch64
      user-space canonical addressing satisfies this.

Both AOS target arches are 64-bit, 8-byte-aligned, canonical-address platforms,
so the representation is portable across them unchanged. 32-bit is excluded not
as a convenience but because the value representation *cannot* be made
bit-compatible there — and AOS targets no 32-bit host, so there is no reason to
carry a second value layout.

### 3.2 Cranelift targets both arches; the tree-walk oracle is arch-neutral

[execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) compiles
hot thunks via Cranelift, which has mature x86-64 and aarch64 backends; the
tier-0 tree-walking interpreter (the correctness oracle of
[compatibility constraints](02-compatibility-constraints.md) §7.4) is portable
Rust with no arch assumptions. The optimized tiers are *where* host architecture
shows up — different machine code, different register allocation, different
inline-cache shapes in memory — and they are precisely the part that the
invariant in §3.3 forbids from leaking into output.

### 3.3 The invariant: codegen affects speed, never output

The single most important property of multi-arch support is that it is
**output-invisible**:

```text
   x86-64 host                          aarch64 host
   ───────────                          ────────────
   parse -> IR -> Cranelift(x86-64)     parse -> IR -> Cranelift(aarch64)
        │  (faster/slower codegen)           │  (faster/slower codegen)
        ▼                                     ▼
   force thunks, build derivation        force thunks, build derivation
        │                                     │
        ▼                                     ▼
   nix-compat ATerm + SHA-256            nix-compat ATerm + SHA-256
        │                                     │
        └──────────► IDENTICAL .drv ◄─────────┘
            (same builtins.currentSystem ⇒ same store paths, same bytes)
```

Host architecture is, by the admissibility rule of
[compatibility constraints](02-compatibility-constraints.md) §6, an *internal*
concern: it changes which machine code runs, never which value is computed. The
NaN-box layout, the Cranelift IR, and register allocation all sit in the
"internal" column of the observable table and may differ freely between hosts.
What lands in the `.drv` is the ATerm produced by `nix-compat`, a function of the
*values* forced, and those values do not depend on the host's instruction set —
the same defense-in-depth as the JIT-vs-oracle relation in
[execution tiers](08-execution-tiers-and-cranelift.md): the fast, host-specific
path must produce the slow path's answer or it is a bug.

> **Harness obligation.** The differential harness must include a **cross-host**
> check: instantiate the AOS closure on an x86-64 builder and on an aarch64
> builder (pinning `builtins.currentSystem` identically) and assert the
> resulting `.drv` closures are byte-identical to each other and to `NixCli`.
> This is over and above the per-host `aos-nix`-vs-`NixCli` gate; it certifies
> that the *speed/output split* actually holds in practice and that no
> arch-specific codegen detail leaked into a hash. See
> [differential testing](15-differential-testing-and-benchmarking.md).

### 3.4 `currentSystem` / `system` must report the target, not the host

The store path of a derivation embeds its `platform` field (e.g.
`"x86_64-linux"`) directly in the ATerm
([compatibility constraints](02-compatibility-constraints.md) §4.2), and most
AOS expressions derive that platform from `builtins.currentSystem`. So:

- [ ] **`builtins.currentSystem` and `builtins.system`** must report the
      configured **target system string** — the platform AOS is building *for* —
      not an introspected host triple. This matters for two reasons: parity
      (C++ Nix's `currentSystem` is the configured/overridable platform
      identifier, per the manual, not `uname`), and AOS **cross-builds**, where
      an x86-64 host legitimately evaluates with `currentSystem =
      "aarch64-linux"` to produce aarch64 derivations.
- [ ] Because `currentSystem` is configurable/overridable (and is *unavailable*
      under `--pure-eval`, §2.1), aos-nix takes its value from the same
      configuration channel C++ Nix does (the `system` setting / override), so
      that the host an evaluation happens to run on is invisible to the `.drv`.
      The cross-host identity invariant of §3.3 is, restated, exactly the claim
      that fixing this one string fixes the whole output regardless of host.

---

## 3.5 Operating-system support: Linux and macOS

aos-nix targets **both Linux and macOS (Darwin)**, exactly as upstream vanilla
Nix does — Nix is used as heavily on macOS for development as on Linux, and the
evaluator must run natively on both even though AOS-the-distribution is Linux.
The host-independence invariant of §3.3 extends from architecture to OS:
**the host operating system affects evaluation *speed*, never evaluation
*output*** — the same `.nix` evaluates to the same `.drv` on a Linux host and a
macOS host for a given `builtins.currentSystem`. The differential harness
([15](15-differential-testing-and-benchmarking.md)) runs on both OSes, each
against its platform's `nix-instantiate`, and `currentSystem` reports the Darwin
strings (`x86_64-darwin`, `aarch64-darwin`) on macOS.

**Decision (closed): portable by default; OS-specific optimizations behind
`#[cfg]` build gates with correct portable fallbacks.** Nothing OS-specific is
allowed to change observable behavior — it may only change performance. The two
directions of OS-specific code:

- **Linux-only optimizations, `#[cfg(target_os = "linux")]`-gated.** The
  page-level cooperation in [memory management](06-memory-management-and-gc.md)
  §3.5 — `madvise(MADV_PAGEOUT/MADV_COLD)` and transparent huge pages
  (`MADV_HUGEPAGE`) — does not exist with the same semantics on macOS. These sit
  behind the `advise_*` portability shim (06 §3.5), which lowers to the best
  available primitive per platform and **falls back to a no-op** where the OS
  lacks it. Because paging advice is observationally invisible (06 §8), the
  fallback is always correct; macOS simply forgoes those particular peak-memory
  optimizations.
- **macOS-only code, `#[cfg(target_os = "macos")]`-gated.** The JIT
  ([execution tiers](08-execution-tiers-and-cranelift.md)) needs Apple Silicon's
  hardened-runtime W^X handling (`MAP_JIT` + per-thread
  `pthread_jit_write_protect_np()`) on `aarch64-darwin`; this is macOS-specific
  plumbing the Linux build does not compile. Cranelift, fibers, the `mmap`'d CA
  store, and the LLVM AOT tier are otherwise portable across both OSes.

Two platforms × two architectures (`{x86_64, aarch64} × {linux, darwin}`) is the
support matrix, matching vanilla Nix; 32-bit and other OSes are out of scope
(§3.3). The CI differential harness is run on at least one Linux and one macOS
target so OS-specific code paths are parity-checked, not just compiled.

---

## 4. `nixVersion` / `langVersion` spoofing is a parity requirement

> **Decision.** aos-nix MUST report the **exact pinned C++ Nix version** via
> `builtins.nixVersion` and that version's language-version integer via
> `builtins.langVersion` — not an aos-nix version of its own, and not a sentinel.
> This is a **parity requirement, not a cosmetic courtesy**: version-gated code
> in nixpkgs and AOS branches on these values, and a different branch yields a
> different `.drv`.

### 4.1 Why a wrong version string silently corrupts the `.drv`

`builtins.nixVersion` is a string giving the Nix version (e.g. `"2.16.0"`);
`builtins.langVersion` is an integer giving the Nix-language version. Library
code uses them to feature-gate. The canonical idiom is
`lib.versionAtLeast builtins.nixVersion "2.x"` — `versionAtLeast v1 v2` returns
true when `v1` is at least `v2` — wrapped around a conditional that selects
between two implementations of the *same* derivation. Recent nixpkgs even
*requires* `builtins.nixVersion` to report at least `2.18` and gates on it. The
failure mode is exactly the catastrophic one from
[compatibility constraints](02-compatibility-constraints.md) §3:

```text
   lib.versionAtLeast builtins.nixVersion "2.18"
        │
        ├─ true  (C++ Nix reports the real pinned version) ─► branch A ─► .drv_A
        │
        └─ false (aos-nix reports its own version string)  ─► branch B ─► .drv_B
                                                                 │
                                                          .drv_A ≠ .drv_B
                                                                 │
                                                          cache miss, fan-out,
                                                          from-source rebuild
```

If aos-nix reported its *own* identity, every version-gated expression in the
closure could take the *other* branch from C++ Nix, producing a systematically
different `.drv` graph — the Merkle fan-out of
[compatibility constraints](02-compatibility-constraints.md) §3 turns one wrong
string into a whole-distribution rebuild. The version string is an **observable
input to evaluation**, in the same category as attribute iteration order:
invisible until it changes a branch, then catastrophic.

### 4.2 Spoofing is the correct, principled choice

- [ ] aos-nix **is** an implementation of the pinned C++ Nix language, by
      construction ([compatibility constraints](02-compatibility-constraints.md)
      commits to bug-for-bug parity with one *pinned* version, constraint C-9).
      Reporting that version is *truthful about the contract*: it asserts "I
      behave as Nix 2.x," exactly the property the gate enforces.
- [ ] The pinned version is a single source of truth shared with the harness:
      the same C++ Nix binary aos-nix is diffed against
      ([differential testing](15-differential-testing-and-benchmarking.md)) is
      the version `builtins.nixVersion` reports. Bumping the pin moves both the
      oracle and the reported string together and re-validates the whole closure,
      so the version string can never drift from the behavior it advertises.
- [x] `langVersion` is spoofed in lockstep: any expression that branches on the
      language version (rarer than `nixVersion`, but it exists) must see the
      pinned value so it selects the pinned-version code path.

> **Restated as parity.** Reporting the pinned version is not pretending to be
> something we are not; it is asserting the one property the entire RFC is built
> to guarantee — that aos-nix and the pinned C++ Nix are extensionally
> indistinguishable at the `.drv` boundary. A version string that said otherwise
> would be the lie.

---

## 5. Summary of decisions

| # | Decision | In/Out | Why it lives here |
|---|---|---|---|
| 1 | Flakes (`getFlake`, `parseFlakeRef`, `flakeRefToString`, lock files, eval cache) | **Out** | No AOS flake workload; a parallel surface as large as the one we already commit to. Falls back to `NixCli`. |
| 2 | `--pure-eval`, `restrict-eval`, allowed-paths/allowed-uris | **In** | Observable: same flags must yield same branches and same eval-time I/O; it is the evaluator's I/O boundary and ties to the cache key. |
| 3 | Multi-arch (x86-64 + aarch64; no 32-bit) | **In** | Value repr + Cranelift target both AOS arches. Invariant: host affects speed, never output — cross-host `.drv` identity, gated. |
| 4 | `nixVersion` / `langVersion` spoofing to the pinned version | **In** | Parity requirement: version gates must take identical branches or the `.drv` diverges and fans out. |

The through-line: scope decisions are parity decisions. Excluding flakes keeps
the parity surface to what the harness can prove over the actual AOS closure;
including the eval modes, both arches, and version spoofing keeps parity
*intact* inside that surface. Anything outside the box falls back to `NixCli`
([integration with AOS](14-integration-with-aos.md)); everything inside it is
held to the byte-identical contract of
[compatibility constraints](02-compatibility-constraints.md). Cross-references:
value layout assumptions in [value representation](05-value-representation.md);
Cranelift arch backends in
[execution tiers and Cranelift](08-execution-tiers-and-cranelift.md); the I/O
mediation in [parallel evaluation](13-parallel-evaluation.md) §5.5 and impure
cache keying in [incremental evaluation cache](12-incremental-evaluation-cache.md);
the cross-host and error-outcome gates in
[differential testing](15-differential-testing-and-benchmarking.md); the
decision record in [decision register](19-decision-register.md).

---

## Implementation checklist

Per-feature tracker for scope, platform, and language modes (flakes-out, restricted/pure-eval + allowed-paths, multi-arch host-independence, and `nixVersion`/`langVersion` spoofing); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

These are **P1** parity decisions: each draws the box around what aos-nix evaluates such that getting it wrong either inflates the parity surface beyond what the harness can prove (flakes) or silently violates parity inside the surface kept (modes, arch, version reporting). All are gated by the differential `.drv` harness ([15](15-differential-testing-and-benchmarking.md)) including its error-outcome and cross-host checks.

### Flakes are out of scope (§1)

- [ ] Stub the three flake builtins (`getFlake`, `parseFlakeRef`, `flakeRefToString`) in the builtin table to raise `NativeEvalError::Unsupported{feature:"flakes"}`, triggering transparent top-level `NixCli` fallback — no partial flake support, no flake fixtures in the harness (the AOS closure contains none); a future flake entry point shows up as a fallback-counter increment, never a divergence (§1.1, §1.3) — **P1**, `C-22`; the excluded surface (`flake.nix` schema, `flake.lock`, flakeref grammar, flake eval cache, `getFlake` impurity rules) is documented as out-of-box (§1.2).

### Restricted / pure-eval modes and allowed-paths (§2)

- [ ] `--pure-eval` semantics matching the pinned C++ Nix *as behaviors*: `currentTime`/`currentSystem`/`storePath` unavailable, `getEnv` not reading the ambient env, `exec` disabled, `$NIX_PATH`/`-I` ignored, fetchers require pinning with no FS access outside fetched paths (§2.1) — **P1**, `C-23`; harness catches a divergent branch as a `.drv` byte diff or an error-outcome mismatch.
- [ ] `restrict-eval` / `allowed-paths` / `allowed-uris` mediating the three eval-time operations (`readFile`/path-coercion, `import`, fetchers) with the *same* admit/refuse decisions C++ Nix makes — match, never innovate; error-class parity on forbidden reads (§2.2) — **P1**, `C-23`.
- [ ] The allowed-paths/allowed-uris check as the single eval-time I/O choke point: a forbidden read refused *before* it becomes an awaited fiber I/O future, and every *permitted* impure read folded into the incremental-cache key so a cached result cannot outlive its input (§2.3) — co-designed with the fiber/tokio model ([13](13-parallel-evaluation.md) §5.5, **P3.5**) and impure-read cache keying ([12](12-incremental-evaluation-cache.md), **P2**), `C-23`/`R-10`.

### Multi-arch portability and the host-independence invariant (§3)

- [ ] Support x86-64 and aarch64 hosts (both AOS targets), 32-bit unsupported — the NaN-boxed/tagged value layout assumes 64-bit words, 8-byte-aligned heap objects, canonical addresses, which hold on both and on neither 32-bit target (§3.1) — **P1** value layout (`S-6`/`M-4`), Cranelift dual-backend **P6** (`S-3`); `C-24`.
- [ ] The critical invariant — host architecture affects eval *speed* (codegen, register allocation, in-memory IC shapes), **never** eval *output*: the same `builtins.currentSystem` yields the byte-identical `.drv` on an x86-64 and an aarch64 host (§3.2, §3.3) — **P1**, `C-24`; defense-in-depth is the same JIT-vs-oracle relation.
- [ ] The cross-host harness obligation: instantiate the AOS closure on an x86-64 builder and an aarch64 builder (pinning `currentSystem` identically) and assert byte-identical `.drv` closures to each other and to `NixCli` — over and above the per-host gate (§3.3) — gated by [15](15-differential-testing-and-benchmarking.md), `C-24`.
- [ ] `currentSystem`/`system` report the configured **target** system string (taken from the same `system`-setting/override channel C++ Nix uses), not an introspected host triple — so cross-builds (x86-64 host, `aarch64-linux` target) and the host an eval runs on stay invisible to the `.drv` (§3.4) — **P1**, `C-24`.

### `nixVersion` / `langVersion` spoofing (§4)

- [x] `builtins.nixVersion` reports the **exact pinned C++ Nix version** aos-nix targets, and `builtins.langVersion` reports that version's language-version integer — a parity requirement, not cosmetic: `lib.versionAtLeast builtins.nixVersion "2.x"` gates must take identical branches or the `.drv` diverges and fans out to a from-source rebuild (§4.1, §4.2) — **P1**, `C-25`; single source of truth shared with the harness oracle (`C-9`), so the string can never drift from the behavior it advertises.

## References

- Nix Reference Manual — Built-ins (`getFlake`, `flakeRefToString`,
  `parseFlakeRef`, `currentSystem`, `nixVersion`, `langVersion`):
  <https://nix.dev/manual/nix/2.33/language/builtins>
- Nix Reference Manual — Built-in Constants (`currentSystem`, `nixVersion`,
  `langVersion`, `storePath`; "Not available in pure evaluation mode"):
  <https://nix.dev/manual/nix/2.18/language/builtin-constants>
- `builtins.getFlake` — locked-flake-ref requirement unless `--impure`:
  <https://noogle.dev/f/builtins/getFlake>
- Nix — "Add pure evaluation mode" (commit defining `--pure-eval`: disables
  `currentTime`/`currentSystem`/`storePath`, ignores `$NIX_PATH`/`-I`, requires
  fetcher hashes, no FS access outside fetched paths):
  <https://github.com/NixOS/nix/commit/d4dcffd64349bb52ad5f1b184bee5cc7c2be73b4>
- Nix Reference Manual — `nix.conf` (`restrict-eval`, `allowed-uris`,
  `pure-eval`, `allowed-impure-host-deps`):
  <https://nix.dev/manual/nix/2.18/command-ref/conf-file>
- Nix Reference Manual — `nix eval` (`--impure` / pure-eval interaction):
  <https://nix.dev/manual/nix/2.18/command-ref/new-cli/nix3-eval>
- NixOS Discourse — "access to absolute path … is forbidden in pure eval mode
  (use `--impure` to override)" (observable pure-eval refusal text):
  <https://discourse.nixos.org/t/error-access-to-absolute-path-nix-store-elements-basic-nix-is-forbidden-in-pure-eval-mode-use-impure-to-override/46535>
- `lib.versionAtLeast` — Nix function reference (version-gating semantics):
  <https://noogle.dev/f/lib/versionAtLeast/>
- NixOS/nixpkgs #461925 — nixpkgs requiring `builtins.nixVersion` >= a minimum
  (feature gating on the reported Nix version):
  <https://github.com/nixos/nixpkgs/issues/461925>
- NixOS/nixpkgs #75149 — `versionAtLeast` and the Nix version string (pre-release
  parsing caveat relevant to spoofing the exact pinned string):
  <https://github.com/NixOS/nixpkgs/issues/75149>
