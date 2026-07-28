# Instruction-Bloat Attribution: Per-Symbol Profiles + Per-Op Budgets

Status: **RESOLVED (2026-07-15). The bloat is UNIFORM, not amplified.** The
builder runs are in (§6); the toplevel executes **~4.6x the instructions per
function call vs C++** at near-equal IPC, and a file-free compute microbench
carries the *same* per-op tax — so there is no toplevel-specific amplifier
(imports/depth/module machinery are exonerated, §7). Attack the shared per-op
eval-loop tax globally. The instruction-diet method is validated (moves the
number, 546-green) but its realistic floor is **~3.0-3.7x C++**; the residual is
architectural (§8). Tooling: `AOS_NIX_BENCH_COLD_ONLY` (landed). §§1-5 are the
methodology and commands; §§6-8 are the results and verdict.

**2026-07-23 Candidate-C refresh.** On the current PR build after gating
diagnostic FV dereference counters, bypassing process-global reservation
lookups where the serial heap already owns the address context, carrying the
active lexical environment as a persistent frame-chain head, and returning
already-WHNF node results before the lazy-identity helper, caching the
native-stack floor used by recursive node-entry protection, and specializing
the inline-capture allocation door, then compacting the common captured
environment and thunk payload, isolated cache-off
`systems.server.build.toplevel` evaluations retire
**22.8920-22.8943B instructions at IPC 2.78-2.79**. Pinned C++ Nix 2.24.12
retires **6.2186B at IPC 2.84** for byte-identical output. Function-call counts
remain nearly identical (3.177M native versus 3.163M C++), so the current
live-load gap is **3.68x in instructions and about 3.66x in
instructions/function-call**, with no IPC deficit that could explain it. A
prior separate three-sample wall run measured 1.980s versus 0.554s, or
**3.58x slower**; wall time on the shared builder remains secondary to retired
instructions. The absolute gap has improved since the original audit; its
uniform per-operation character has not changed.

**2026-07-24 full-load stall audit.** A primed repeat of the same
`systems.server.build.toplevel` load measured 2.79 CPU seconds in 2.80 wall
seconds for Candidate C (99% CPU), versus 0.48 CPU seconds in 0.54 wall seconds
for pinned C++. Candidate C reported 1.32 system seconds and 238,151 minor
faults, versus 0.09 system seconds and 84,013 minor faults for C++; both had
zero major faults and zero filesystem input. One-second `pidstat` samples
showed 99-100% CPU, 0% wait, zero block-I/O throughput, and zero I/O delay.
Thus the observed 5.2x wall sample was not file-I/O or scheduler waiting: it
contained about 5.8x as much CPU time. Candidate C's excess page footprint is
also a CPU cost through demand-zero minor faults, not merely a memory-score
problem. A syscall trace showed only about 14ms in the one `nix-store
--realise` child; the large cumulative `futex` duration came from idle runtime
threads and must not be mistaken for main-thread evaluation CPU.

## 1. The finding that reopened the game

`perf stat` on the cold toplevel shows the 5x wall gap is **instruction count**,
not stalls, at **equal IPC**:

- C++ Nix: **6.24e9** instructions @ IPC **2.83** for the whole toplevel.
- Us: **99e9** instructions @ IPC **2.51** for the bench process (~**30e9 per
  cold eval**).
- **Op counts match** (counter-diff verified): same number of function calls,
  thunks, values. So we execute **~2000-2500 instructions per op vs C++'s
  ~500**, at essentially equal IPC.

This is why **every cycle-profile was flat** (RFC-0007 perf campaign, no entry
>8.1%): uniform per-op instruction bloat is invisible to cycle sampling — if
every op costs 4-5x its instructions uniformly, no single symbol stands out in a
cycle profile, because cycles track the *stall* structure, not the *instruction*
structure. The right lens is a **retired-instruction** profile and a **per-op
instruction budget**, which this note builds.

The prize: closing a 5x instruction gap at equal IPC is a ~5x wall win — the
entire toplevel-parity target — and unlike the JIT (ruled out for the toplevel
in `jit-fuse-shapes-economics.md`), a per-op instruction reduction attacks the
flat long tail directly, which is exactly where the mass is.

## 2. The two questions, and the metrics that answer them

**Q1 (localization): which code is instruction-dense?** A symbol is
instruction-dense when its share of retired instructions **exceeds** its share of
cycles (`instr% > cycle%`, i.e. low CPI — many cheap instructions); it is
stall-y when `cycle% > instr%`. Ranking symbols by `instr% − cycle%` (or the
ratio) localizes the bloat to specific functions. A cycle profile alone cannot
do this; we need both events and a per-symbol join.

**Q2 (Dylan's — uniform or amplified?): is per-op instruction count uniform
across shapes, or does the toplevel have a shape-specific amplifier?** Compute
`instructions_per_op = clean_cold_instructions / cold_ops` for three contrasting
workloads:

- **`attr-fixpoint`** (`tests/bench/compute.nix`) — the module-ish shape: a
  `fix` + `extends` overlay chain with a quadratic `//` merge, deep-ish env, but
  **no imports, no derivations, no store I/O**.
- **`pkgs.zlib`** — a single real package: moderate env depth, a derivation, some
  imports.
- **toplevel** (`system.build.toplevel`) — deep module fixpoint, huge env, ~459
  imports, derivation machinery.

Decision rule:

- toplevel per-op ≈ zlib per-op ≈ attr-fixpoint per-op → **uniform bloat**;
  attack globally (the per-op interpreter tax lives in the shared force/apply/
  var-resolve/validation layers — see the per-op instruction-tax ledger,
  task #22).
- toplevel per-op is **2-3x** zlib/attr-fixpoint per-op → a **shape amplifier**
  scaling with env depth / select-chain length / import machinery is the target
  (env-depth histograms, task #23). The `attr-fixpoint`-vs-`zlib` contrast
  isolates the fixpoint/env shape from the import/derivation machinery: if
  `attr-fixpoint` per-op ≈ toplevel per-op, the amplifier is the fixpoint/env
  shape itself; if `attr-fixpoint` ≈ zlib (low) while toplevel is high, the
  amplifier is import/derivation/module machinery.

## 3. Run commands (lead executes on the builder)

### 3.0 The clean-cold instrument: `AOS_NIX_BENCH_COLD_ONLY`

`AOS_NIX_BENCH_COLD_ONLY=1 aos nix-bench` (landed this commit) runs **exactly one
isolated native-only cold eval per `-A` attribute** — no C++ oracle, no warm
re-instantiate, no parity gate, no history. So a `perf stat` wrapping the process
counts **one cold eval's** retired instructions (plus fixed process startup),
with **no C++ subprocess** polluting the count. It prints one greppable line per
attr: `aos_nix_cold_only {"attr":…,"drv":…,"wall_ns":…}`. `-A` is required (this
path builds no oracle, so it cannot discover attributes).

Here **cold** means that no cache data enters from an earlier run. The isolated
candidate clears persistent roots and disables disk/network tiers, but enables
every applicable same-run tier: serial evaluation gets the content-memo L0 and
the GC-off worker-local Ready directory, while a shared parallel-demand context
also gets L1. An earlier helper enabled L0/L1 but accidentally left the Ready
directory off; benchmarks before that fix understate legal intra-run reuse.

`--eval-system` and `--impure-eval` are **global** flags — put them before the
subcommand. All commands assume `x86_64-linux`.

### 3.1 Per-op instruction budget (native, clean cold) — the Q2 table

Run **two** processes per workload; the instruction numerator comes from the
CLEAN run (no `AOS_NIX_EVAL_STATS`, which would add the census's ~742 ns/force
bookkeeping *instructions* to the count), the op denominator from the STATS run
(same deterministic cold eval, so the op counts are identical):

```text
# (a) CLEAN instruction + cycle count for one cold eval:
perf stat -e instructions:u,cycles:u -- \
  env AOS_NIX_BENCH_COLD_ONLY=1 aos --eval-system x86_64-linux --impure-eval \
      nix-bench -A pkgs.zlib

# (b) op counters + force-shape census for the SAME cold eval:
AOS_NIX_EVAL_STATS=1 AOS_NIX_BENCH_COLD_ONLY=1 \
  aos --eval-system x86_64-linux --impure-eval nix-bench -A pkgs.zlib \
  2>&1 | grep -E 'aos_nix_eval_stats|aos_nix_force_shape_census'
```

Repeat both for: `-A attr-fixpoint --file tests/bench/compute.nix`,
`-A pkgs.zlib`, and the toplevel attribute
`-A systems.<system-name>.build.toplevel` (the same attr the census run used;
the harness derives it as `systems.${name}.build.toplevel` over the default
`default.nix`). Also grab two more compute shapes for range: `-A fib` and
`-A lambda-interp` (`--file tests/bench/compute.nix`).

Per-op budget = `instructions (a) / function_calls (b)`. Report `function_calls`
as the primary op (cross-comparable to C++ `nrFunctionCalls`); also compute
against `thunks_forced` and `values_allocated` as secondary denominators, and
per-op against the census `total_forces`.

### 3.2 Per-symbol density profile (native) — the Q1 ranking

Two records per workload (one instructions, one cycles), same cold-only command:

```text
perf record -o zlib.insns.data -e instructions:u -g -- \
  env AOS_NIX_BENCH_COLD_ONLY=1 aos --eval-system x86_64-linux --impure-eval nix-bench -A pkgs.zlib
perf record -o zlib.cycles.data -e cycles:u -g -- \
  env AOS_NIX_BENCH_COLD_ONLY=1 aos --eval-system x86_64-linux --impure-eval nix-bench -A pkgs.zlib

perf report -i zlib.insns.data  --stdio -n --percent-limit 0.5 --sort symbol > zlib.insns.report
perf report -i zlib.cycles.data --stdio -n --percent-limit 0.5 --sort symbol > zlib.cycles.report
```

Send both `.report` files (toplevel + zlib + attr-fixpoint). I join by symbol and
rank by `instr% − cycle%` to produce the instruction-density table. (If a single
grouped record is preferred: `perf record -e '{instructions:u,cycles:u}:S' …`
then `perf report --group`.)

### 3.3 C++ per-op budget (zlib, toplevel) — the comparison

`nix-instantiate` is a separate process, directly comparable to cold-only
(both parse + eval + write the `.drv`):

```text
NIX_SHOW_STATS=1 NIX_SHOW_STATS_PATH=/tmp/cxx-zlib.json \
  perf stat -e instructions:u,cycles:u -- \
  nix-instantiate <default.nix> -A zlib --eval-system x86_64-linux
```

C++ per-op = `instructions / nrFunctionCalls` (from `/tmp/cxx-zlib.json`). Repeat
for the toplevel attr. This anchors our per-op budgets against the ~500
instructions/op target.

## 4. Analysis tables to fill (on data return)

**T1 — Per-op instruction budget (the Q2 verdict).**

| workload | instructions (clean cold) | function_calls | **insns/call** | vs zlib | vs C++ |
|---|---|---|---|---|---|
| attr-fixpoint | | | | | (n/a) |
| fib | | | | | (n/a) |
| lambda-interp | | | | | (n/a) |
| pkgs.zlib | | | | 1.00 | |
| toplevel | | | | | |
| C++ zlib | | | ~500? | | 1.00 |
| C++ toplevel | | | ~500? | | |

Verdict cell: toplevel÷zlib ratio. ≈1 → uniform (attack the shared per-op tax,
task #22); ≥2 → amplifier (attack the env-depth/import shape, task #23), and the
attr-fixpoint row says which amplifier.

**T2 — Instruction-density ranking (the Q1 localization).** Per symbol: `instr%`,
`cycle%`, `instr% − cycle%`, CPI. Top instruction-dense symbols are the global
per-op-tax targets; the toplevel-minus-zlib delta in a symbol's `instr%` localizes
any amplifier to specific code.

**T3 — Cross-workload symbol delta.** For the amplifier hypothesis: symbols whose
`instr%` rises sharply from zlib→toplevel are the amplifier's home (expect
env-walk / select-IC / import-resolve / attrset-merge functions if the amplifier
is real).

## 5. Notes / caveats

- **Do not read the instruction numerator from an `AOS_NIX_EVAL_STATS` run** —
  the census + eval-stats bookkeeping executes real instructions (~742 ns/force
  of work) that inflate the count. Numerator = clean run; denominator (ops) =
  stats run; the cold eval is deterministic so the op counts transfer.
- **Process-startup floor.** cold-only still pays `aos` process startup. Measure
  it once (`perf stat -e instructions:u -- env AOS_NIX_BENCH_COLD_ONLY=1 aos
  --eval-system x86_64-linux --impure-eval nix-bench -A '<trivial attr>'`, e.g. a
  literal-returning attr) and subtract, or note it's small vs ~30e9.
- **DSO-filter fallback (no tooling).** If a full `aos nix-bench` run is used
  instead of cold-only, `perf report --sort dso,symbol` separates our binary's
  instructions from `libexpr`/`nix-instantiate`, so native-vs-C++ can be split
  from one record — but it mixes cold+warm evals, so use cold-only for clean
  per-op *budgets* and reserve the DSO split for a quick native/C++ ratio.
- IPC is already known equal (2.5 vs 2.8); the campaign is about the instruction
  *count*, so the instructions:u event is the load-bearing one. Cycles are
  recorded only to compute per-symbol CPI for the Q1 density split.

---

## 6. Results — builder run, 2026-07-15

Clean cold-only budgets (this note's `AOS_NIX_BENCH_COLD_ONLY` instrument;
retired instructions **floor-subtracted** — process-startup floor is 135.8M for
a `default.nix`/`pkgs.*` entry and ~80M for a `--file tests/bench/compute.nix`
entry). Ops are the same eval's `AOS_NIX_EVAL_STATS` counters. `function_calls`
is the primary denominator — it is the one op both engines count identically
(`function_calls` ↔ C++ `nrFunctionCalls`) **and it matched** (us 3,176,661 vs
C++ 3,163,115 on the toplevel, 0.4% apart), which is what makes "same work,
more instructions" a fair claim.

### T1 — per-op instruction budget

| workload | gross insns | net insns | IPC | wall (s) | **insns/call** | insns/force | insns/(call+force) |
|---|---|---|---|---|---|---|---|
| pkgs.zlib | 703.4M | 567.6M | 2.19 | 0.083 | 93,494 | 48,192 | 31,800 |
| attr-fixpoint | 9.69e9 | 9.61e9 | 4.78 | 0.47 | 155,900 | 335,451 | 106,435 |
| **toplevel** | 28.79e9 | 28.65e9 | 2.44 | 2.41 | **9,020** | 9,738 | 4,683 |
| lambda-interp | 77.48e9 | 77.40e9 | 2.49 | 6.26 | 11,327 | 10,927 | 5,562 |
| **C++ toplevel** | 6.258e9 | — | 2.81 | 0.572 | **1,978** | 2,239¹ | 752² |
| C++ zlib | 494.5M | — | 2.43 | 0.061 | — | — | — |

¹ per (call + `nrThunks`). ² per (call + `nrThunks` + `nrPrimOpCalls`); this is
the ~750/op figure — it just spreads the same instructions over a larger op
count, so it is not comparable to our call-based number. Use **insns/call** for
the cross-engine ratio.

### Cross-engine, toplevel

- **insns/call: us 9,020 vs C++ 1,978 = 4.56x.** Gross instructions 4.60x, wall
  4.21x, IPC near-equal (2.44 vs 2.81). At matched call counts we retire ~4.6x
  the instructions per call.

## 7. Verdict — the bloat is UNIFORM (no toplevel amplifier)

Three independent legs, each ruling out a shape-specific amplifier, plus the
zlib corollary that localizes the tax:

**Leg 1 — file-free parity (the decisive one).** `lambda-interp` is a pure
λ-calculus compute microbench (a Brainfuck interpreter): **zero imports, zero
file reads, zero derivations, no module fixpoint.** It costs **11,327 insns/call
and 10,927 insns/force** — *higher* than the toplevel's 9,020/call and
9,738/force. A workload with none of the toplevel's "amplifier" machinery pays
the *same* (slightly higher) per-op tax. So the per-op cost is the baseline cost
of the eval loop itself, not anything the toplevel adds. If an
import/module/depth amplifier existed, the toplevel per-op would *exceed* the
file-free microbench; it does not.

**Leg 2 — depth exoneration** (env-depth instrument, task #23). Toplevel
install-env depth averages **0.34 (89% length-0**, max bucket 5-8); capture depth
averages 6.13. These are shallow and in line with zlib (0.22 / 2.77) and
attr-fixpoint (0.31 / 3.32). Env-chain length does not scale the per-op cost —
there is no O(depth) amplifier in the hot path.

**Leg 3 — imports are a rounding error** (per-import timer, task #25). Toplevel
import machinery is **io+fingerprint 5.1ms + module_setup 1.0ms = 6.1ms** of a
2.41s eval (**0.25%**); the whole front-end (parse+resolve+lower+annotate) is
~55ms (**2.3%**). The ~459 imports Dylan flagged cost single-digit milliseconds,
not a 4x factor.

**Corollary — why zlib is near-parity, and what that localizes.** zlib is
**567.6M net vs C++ 494.5M = 1.15x** (1.42x gross) — essentially at parity, not
5x. zlib's instruction mass is front-end (parse) plus derivation/hash/IO
primops, shared-cost work already close to C++, and it makes only **6,071 calls /
11,778 forces** — it barely touches the eval loop. The 4.6x tax is invisible on
zlib precisely because zlib does little call/force work. This **localizes the
tax to the eval loop** — the per-call/per-force/per-var-resolve path the toplevel
hits 3.2M times — and away from the front-end and primops.

**Conclusion.** The 4.6x is a uniform per-op tax on the interpreter's core
call/force/resolve loop, identical in a file-free microbench and the full
system. Attack it **globally** (the per-op instruction-tax ledger, task #22),
not via any toplevel-specific amplifier (imports #25 and depth #23 are both
ruled out).

## 8. Diet scoreboard and honest remaining runway

**Scoreboard (validates the method).** The per-op ledger's removable classes are
real and byte-safe:

| lever batch | insns | cycles |
|---|---|---|
| flagship (box `TreeWalkError`, #26) + lever 2 (collapse double value-resolve, #28) | −3.0% | −7-10% |
| levers 4-6 (capture-atomics gate, inline audit, free wins, #27) | −0.9% | — |
| **cumulative** | **28.79e9 → 27.68e9 = −3.86%** | — |

546-green throughout — the instruction-diet method works and preserves .drv byte
parity.

**Runway (honest).** Parity with C++ means removing **78%** of instructions
(28.79e9 → 6.26e9), a 4.6x per-op reduction. Diet arithmetic:

| removed | result | vs C++ | insns/call |
|---|---|---|---|
| 3.86% (done) | 27.68e9 | 4.42x | ~8,670 |
| 3.86% + ledger tail 10% | 24.80e9 | 3.96x | ~7,800 |
| 3.86% + ledger tail 15% | 23.36e9 | 3.73x | ~7,340 |
| optimistic 30% total | 20.15e9 | 3.22x | ~6,300 |

The per-op ledger tail is estimated at ~10-15%, so the **realistic instruction-
diet floor is ~3.7-4.0x C++**, and even an aggressive 30% total reaches only
~3.2x. **Instruction diet alone does not reach parity.** The residual ~3.2-3.7x
is the architectural per-op cost of a Rust tree-walking interpreter — `Result`+
`Span` error propagation, bounds-checked arena indexing, thunk-cell indirection,
Rc refcount traffic — against C++'s raw-pointer hand-tuned loop. Closing it needs
a change to the per-op execution model (a bytecode / threaded / register
interpreter, or the flat-value + arena-env restructuring already in flight),
**not** more diet passes.

**Framing for Dylan.** The instruction-bloat lever is real and worth harvesting:
the diet floor (~3.2-3.7x C++, from today's 4.6x) closes roughly a third of the
gap and is the best available near-term win now that JIT-for-toplevel is closed.
But it is a *floor*, not parity: the last ~3x is an architectural property of the
interpreter's per-op path and requires an execution-model change to remove. The
target should be re-stated as "harvest the diet to ~3x, then decide whether an
architectural interpreter change is on the table" — that decision is Dylan's, not
an incremental diet lever.
