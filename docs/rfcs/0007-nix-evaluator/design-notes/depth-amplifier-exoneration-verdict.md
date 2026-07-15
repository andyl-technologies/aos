# Depth-amplifier — verdict: EXONERATED; the toplevel per-op bloat is uniform

Owner: p1a-env. Task #23 (instruction-bloat campaign, depth lane). **Question:
does the module fixpoint's deeper environments make per-op cost scale with
lexical depth — a shape-linear instruction amplifier on top of the uniform
per-op budget?**

> **STATUS 2026-07-15 — CLOSED, depth EXONERATED.** Environment INSTALLS
> (`clone_env_frames`, the `O(depth)` per-apply/force work) are shallow on every
> workload — toplevel average depth **0.34**, `pkgs.zlib` **0.22**,
> attr-fixpoint **0.31**, none deeper on the toplevel. Captures are ~2x deeper
> on the toplevel (6.1 vs 2.8) but `capture_env` is ~2.6% of cycles, so that is
> ~1-2 points, not a 5x amplifier. The 5x instruction bloat is UNIFORM per-op
> (~2000-2500 insn/op vs C++'s ~500), not depth-linear. The `O(1)`-env-install
> re-entry condition stays CLOSED — more finally than stage B's regression did:
> there is no depth mass to save.

Mirrors the L2 and FV-6 closes: a lever ruled out by direct measurement.

## The measurement (depth probe `0b9a5f00d`, cold, three workloads)

`AOS_NIX_DEPTH_PROBE=1`, install = `clone_env_frames` (per apply/force), capture
= `capture_env` (per closure); `avg = depth_mass / total` frames.

| workload | install total | install avg | capture total | capture avg |
|----------|--------------:|------------:|--------------:|------------:|
| `systems.server.build.toplevel` | 4,861,469 | **0.34** | 2,440,818 | 6.13 |
| `pkgs.zlib` | 16,646 | **0.22** | 14,896 | 2.77 |
| attr-fixpoint | 81,775 | **0.31** | 48,785 | 3.32 |

Toplevel install distribution: `len0`=4,337,813 (**89.2% empty** — no shared
frames to walk), `len1`=20,664, `len2`=176,853, `len3_4`=253,049,
`len5_8`=73,090, **nothing ≥9**. Non-empty installs average
`1,666,631 / 523,656` = **3.18 frames**. Toplevel capture distribution:
`len3_4`=407,841, `len5_8`=1,291,012, `len9_16`=589,704, nothing ≥17.

## Finding 1 — installs are shallow everywhere; no install-side amplifier

The `O(depth)` cost lives at the install (`clone_env_frames` walks the captured
chain per apply/force). Its average depth is **0.34 on the toplevel vs 0.22 on
zlib** — the toplevel is not meaningfully deeper, and both are far below 1
because 89% of installs capture no shared frames at all (consistent with the
apply-count histogram). Even non-empty installs average ~3 frames, capped at the
5-8 bucket. There is no depth mass for an `O(1)` install to save.

## Finding 2 — captures are mildly deeper, with bounded impact

Closure captures ARE deeper on the toplevel (avg 6.1 vs zlib 2.8 — the module
fixpoint does build taller lexical scopes at closure-creation time). But
`capture_env` is ~2.6% of cycles, so a 2x on it moves the total by ~1-2 points,
not a factor. This is the one place the fixpoint's depth shows, and it is not
where the 5x lives.

## Finding 3 — the per-op budget is uniform (independent leg)

`bench.compute.lambda-interp` runs at ~5,600 insn/op with **zero files or
modules loaded** — *higher* than the toplevel's ~4,700 insn/op. A workload with
no depth, no imports, and no module system already carries the full per-op
instruction tax, so the tax is intrinsic to the per-op path, not amplified by
the toplevel's shape.

## Verdict

Three independent legs — shallow installs, bounded-impact captures, and a
depth-free microbenchmark at an even higher per-op budget — converge: the 5x is
**uniform per-op instruction bloat** (~2000-2500 vs C++'s ~500), not a
depth-linear amplifier specific to the toplevel. The lever is the per-op budget
itself (the instruction-tax ledger / JIT lane), not the environment shape.

## Re-entry condition

The `O(1)` env install (stage B's shared-flattened base) stays **CLOSED**. Stage
B was reverted on a measured ~10% regression; this data closes it more finally
by removing the target: with install depth averaging 0.34 (89% empty, non-empty
~3 frames), there is no `O(depth)` mass for an `O(1)` install to eliminate.
Revisit only if a future profile shows `clone_env_frames` install depth rising
into the tens (it is not close), which the module fixpoint's shape does not
produce.
