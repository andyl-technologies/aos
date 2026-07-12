# RFC-0007 — Parallel / speculative front-end implementation plan (design note)

> Design-only prep for the parallel and speculative front-end (task #3 / doc 22
> "Tier 1a"), the code side of decision **C-19** ("parse and compile are lazy,
> parallel, speculative graph nodes"). This note traces how parse/lower actually
> runs today at `HEAD` — serial cold path, the isolated-parse+remap path, and the
> incidental parallelism the L2 demand pool already gives — cites every seam by
> `file:line`, measures the static-import fraction on the AOS corpus, and proposes
> a staged, parity-gated landing order for a parse-ahead scheduler with
> error-quarantined speculation. It is a plan, not an implementation; no code was
> changed and no build was run to produce it. Doc-vs-code divergences are called
> out in §7.
>
> Companion specs: [04 §9.6](../04-frontend-parser-and-ir.md) (the C-19 design
> paragraph and the error-quarantine rule), [13](../13-parallel-evaluation.md)
> (L1/L2 discipline), [19](../19-decision-register.md) (C-19, C-20, M-23, S-23),
> [03 §3.4](../03-architecture-overview.md) (unified demand graph, effect class).
>
> Load-bearing prior state: the L2 parallel-eval program (P0–P4) is COMPLETE and
> its worker infrastructure — a hand-rolled `std::thread` helper pool with
> Chase-Lev deques, a demand queue, and prefix-replica shared logs — is what this
> plan schedules on. See `aos-nix-l2-parallel-eval` in project memory.

## 0. Executive summary

- **Parse/lower is serial on the cold path and only incidentally parallel under
  L2.** With no cache root configured (`self.parse_cache == None`,
  `tree_walk.rs:1262`), every `import` on a cold run parses, resolves, lowers, and
  annotates on the demanding thread via `load_and_eval_import_bytes`
  (`eval_load.rs:102`), which moves the *one* live symbol table into the parser
  with `std::mem::take(&mut self.symbols)` (`eval_load.rs:130`). That `mem::take`
  is the structural reason serial parse cannot overlap: there is a single live
  symbol table and the parser owns it for the duration of the parse.
- **The decoupled path already exists** and is used in two situations: when a
  parse cache is configured (`load_parse_cached_import` →
  `ParseCache::load_or_parse_bytes`, `eval_import.rs:922`, `cache/parse/mod.rs:396`)
  and under parallel mode (`load_and_eval_import_bytes_shared`, `eval_load.rs:199`).
  Both parse into an **isolated** `SymbolTable::new()` off any shared lock, lower,
  then adopt the module by remapping its file-local symbols into the live table
  (`remap_cached_import_ir`, `eval_load.rs:296`). This is exactly the
  "per-worker parse into isolated symbol space + remap-on-adoption" pattern the
  task brief anticipated, and it is the substrate the speculative scheduler
  reuses unchanged.
- **The intern choke point does NOT cap the win.** Adoption interns through
  `intern_symbol_for_eval` (`parallel_demand.rs:754`): a symbol already in the
  prefix replica resolves lock-free; only a *genuinely new* symbol locks the
  `SharedSymbolLog` mutex once (`parallel_demand.rs:135-184`). After the first
  few files the common attribute/identifier vocabulary is resident, so remap is
  overwhelmingly lock-free. The serialization risk is a per-*new-symbol* lock, not
  a per-symbol lock, and new-symbol rate decays sharply across a package set.
- **On the AOS corpus, pure-AST static import edges are the minority of the real
  graph.** There are **110** literal `import ./…`/`../…` sites and **4**
  `import (…)` computed sites across 368 `.nix` files, but the package set is not
  wired by literal imports — it is discovered by `builtins.readDir` and loaded via
  `callPackage (dir + "/${name}")` (`pkgs/default.nix:354-383`), where the path is
  *computed*. `callPackage` itself does `import path` (`pkgs/default.nix:332`), so
  the literal-path edges that speculation can see are the ones passed to
  `callPackage`/`import` **as literals** — which requires speculating on
  path-literal IR nodes generally, not just `import`-argument nodes (**approved
  ruling**, §2). Even then, the top-level `readDir`-driven fan-out is invisible to
  *static* speculation, so a **`readDir`-driven prefetch is planned as its own
  first-class stage** (§3e, §6 S6), framed as a C-19 extension — doc 01 scopes the
  target corpus to AOS's own package set, so covering our actual `readDir` wiring
  is within the RFC's letter. This is the single most important scoping fact in
  this note (§2, §3e, §4).
- **No parse/lower wall timer exists today.** The eval-stats surface counts
  `imports_evaluated` and `import_parse_cache_hits/misses` (`eval_stats.rs:50-55,
  85-89`) but has no parse/resolve/lower/annotate duration counters. The "~25% of
  cold" figure is from external sampling profiles, not an in-eval timer.
  Re-confirming it at `HEAD` is stage **S0** and a precondition for the whole
  effort (§5).
- **Speculation is side-effect-free by construction here** because it stops
  strictly before the demand path's two observable actions — recording the
  import's impure-input fingerprint (`load_and_eval_import`, `eval_load` caller at
  `eval_import.rs:881`) and evaluating the module — and because a parse artifact
  is a pure function of source bytes (`ParseCacheKey::for_source`,
  `cache/parse/mod.rs:96`). The one real side effect it retains is the filesystem
  read, which must be gated by the same access policy the demand path enforces
  (§3b, §6).

## 1. Current state: how parse/lower runs today

### 1a. The cold-eval import path, end to end

`builtins.import x` dispatches to `eval_import_primop` (`eval_import.rs:654`),
which coerces the argument to a filesystem or text-store path, resolves the
realpath (`import_paths`, `eval_import.rs:770` — memoized canonicalization plus a
re-checked access policy), and hands the realpath to `load_cached_import`
(`eval_import.rs:564`). `load_cached_import` is the **import-level memo and
recursion guard**: a `Ready` entry short-circuits with the cached root value and
replays its impure-input trace; an `Evaluating` marker raises `RecursiveImport`;
a miss inserts `Evaluating`, runs the `load` closure, and on success publishes the
result (`eval_import.rs:613-651`). Under parallel mode it first drains the shared
import log (`sync_shared_import_log`, `eval_import.rs:581`) so a file another
worker already finished is adopted rather than re-evaluated (L2-P4,
`parallel_import.rs`).

The `load` closure is `load_and_eval_import` (`eval_load` caller at
`eval_import.rs:695-714`, body at `eval_load.rs:859`). It:

1. reads the source bytes (`fs::read`, `eval_load.rs` via `eval_import.rs:871`),
2. records the import's impure-input fingerprint
   (`record_impure_input_result(ImpureInputFingerprint::import(&path, &source))`,
   `eval_import.rs:881`) — **the first observable effect**,
3. tries the cache path `load_parse_cached_import` (`eval_import.rs:922`), and
4. on a cache hit or configured-cache parse, remaps the cached IR
   (`remap_cached_import_ir`) and evaluates it
   (`load_and_eval_import_ir`, `eval_load.rs:260`); otherwise falls through to
   `load_and_eval_import_bytes` (`eval_load.rs:102`).

### 1b. The two parse implementations

**Serial fast path — `load_and_eval_import_bytes` (`eval_load.rs:102-186`).**
Taken when `self.shared.is_none()` (no parallel pool) *and* the cache path
returned `None` (no cache root). It parses with the live table moved in:

```text
let live_symbols = std::mem::take(&mut self.symbols);           // eval_load.rs:130
let parsed = parse_bytes_with_symbols(source, live_symbols)?;   // grows the table
... resolve ... nix_lower ... annotate_import_ir ...            // eval_load.rs:143-181
self.symbols = std::mem::take(&mut ir.symbols);                 // adopt grown table
```

The comment at `eval_load.rs:125-129` records why: cloning the live table only to
drop it "dominated cold eval," so the table is moved, grown, and moved back. The
consequence for parallelism is structural — **one live table, owned by the parser
for the parse's duration** — so this exact path cannot run two parses at once.

**Decoupled path — the durable cache and the shared parallel path.** Both parse
into a fresh, isolated symbol table and remap on adoption:

- `ParseCache::load_or_parse_bytes` (`cache/parse/mod.rs:396-423`) calls
  `parse_bytes(source)` (fresh table), `resolve`, `nix_lower`. Its key is
  `blake3(personalization ++ schema_version ++ flags ++ source)`
  (`cache/parse/mod.rs:96-105`) — path-independent, pure in the bytes. The durable
  entry is `ir.bin`/`resolved.bin`/`symbols.bin`/`facts.bin`/`meta.toml`
  (`cache/parse/mod.rs:5-14`), shared between workers through the filesystem; each
  worker holds its own cheap `ParseCache` handle (root + schema + flags,
  `Clone`).
- `load_and_eval_import_bytes_shared` (`eval_load.rs:199-259`) is the parallel
  fresh-import path: `parse_bytes_with_symbols(source, SymbolTable::new())`
  (`eval_load.rs:210`), `resolve`, `nix_lower`, `annotate_import_ir`, then
  `remap_cached_import_ir`. Its doc comment (`eval_load.rs:187-197`) states the
  invariant precisely: parsing happens *outside any shared lock*, so "concurrent
  imports of different files still parse in parallel," and interning runs through
  the shared-log choke point only at adoption.

`remap_cached_import_ir` (`eval_load.rs:296-472`) walks the isolated IR and
rewrites every `Symbol` through a `symbol_map` built by interning the file-local
symbols into the live table (`intern_symbol_for_eval`, `eval_load.rs:321`). The
remapped module stores an **empty** per-module symbol table and reads
`self.symbols` at runtime (`eval_load.rs:463-465`), which is the memoized
"no per-import clone" win recorded in project memory.

### 1c. Is parse parallelism live at K≥2? Partially, and only incidentally

Under `TreeWalkOptions::parallel_workers = Some(K)` with `K ≥ 2`, the drivers spawn
`K-1` `std::thread` helpers (`parallel_demand.rs:572`, `HELPER_STACK_SIZE = 16
MiB`, `:115`) sharing one `SharedHeapArena` and the prefix-replica logs. Helpers
steal **Force** and **Coerce** demand tasks (`parallel_demand.rs:84-98`) published
by the `derivation`/`derivationStrict` strict-force fan-out. When a helper forces
a thunk whose body is an `import`, it runs `load_and_eval_import_bytes_shared` and
parses that file on its own thread, off-lock — so two helpers importing two
different files **do** parse concurrently.

But this is a *by-product* of value-demand fan-out, not a front-end scheduler:

- There is **no parse-ahead / speculative work at all** — doc 04 §9.6's
  "speculatively parse along static import edges" is unimplemented (doc 04
  checklist "speculative prefetch" is unchecked).
- Nothing publishes *parse* work to the queue; only `Force`/`Coerce` value work is
  published (`parallel_demand.rs:796-820`). A file is parsed only once the value
  that imports it is already being forced, i.e. never *ahead* of demand.
- Tier-1 JIT is disabled under parallel mode (`native/mod.rs:788-791`), so the
  parallel path is tree-walk only.

### 1d. What serializes, precisely

1. **The live symbol table on the serial fast path** — `mem::take` couples parse
   to `self.symbols` (`eval_load.rs:130`). This is the binding constraint for the
   *serial cold* run and the reason S1 (§6) makes the isolated-parse+remap path
   the serial default.
2. **New-symbol interning under parallel mode** — `intern_symbol_for_eval`
   (`parallel_demand.rs:754-766`) locks `SharedSymbolLog` once per genuinely-new
   symbol. Not per-symbol; not per-file. Measured new-symbol rate across a package
   set decays fast, so this is not the cap (§0).
3. **Single-threaded lower/analyze per file** — `nix_lower` and
   `annotate_import_ir` run on whichever thread owns the parse. They parallelize
   *across* files (isolated inputs) but not *within* a file. Fine: file-level
   granularity is the unit C-19 commits to.

## 2. The static import graph on the AOS corpus

Where import edges are statically visible: an `import` (or `callPackage`, or any
site) applied to a **literal path node** in a file's IR is a static edge —
discoverable from the AST without evaluating anything. A computed argument
(`import (fetchGit …)`, `dir + "/${name}"`, `import someVar`) is not.

Measured over `pkgs/ lib/ modules/ systems/` (368 `.nix` files):

| Form | Count | Statically knowable? |
|---|---|---|
| `import ./…` / `import ../…` (literal path) | 110 | yes — literal Path node |
| `import (…)` (parenthesized/computed) | 4 | no |
| `import <name>` (search-path) | 0 | (n/a for this corpus) |

The 4 computed sites are `pkgs/networking/envoy.nix:503`,
`pkgs/toolchain/go/go.nix:79,424,499` — generated-file imports.

**The decisive fact: the package set is not wired by literal imports.** Packages
are auto-discovered by `discoverPackages` (`pkgs/default.nix:354-383`):
`builtins.readDir dir` → filter names → `callPackage (dir + "/${name}") {}`. The
path `dir + "/${name}"` is computed from the runtime `readDir` result, so the
top-level package fan-out is **invisible to static AST speculation**. The literal
edges that remain are the hand-wired ones — `import ./_source.nix`,
`import ../stdenv/phases.nix` (`pkgs/default.nix:31,343,346,349`), and per-package
sub-file imports.

Two consequences:

- To capture even the hand-wired-and-`callPackage`-literal edges, speculation must
  key on **path-literal IR nodes wherever they appear** (**approved ruling** —
  mandatory on our corpus), not only on nodes that are syntactically the argument
  of `import` — because `callPackage ./foo.nix`
  hides the `import` inside `callPackage`'s body (`pkgs/default.nix:332`). A
  literal Path node that resolves to an existing `.nix` file (or a directory with
  `default.nix`) is a speculation candidate regardless of its syntactic parent.
- Even with that generalization, the AOS corpus caps *static* speculation reach at
  the hand-wired + literal-`callPackage` subset; the `readDir`-driven bulk is
  reached by a separate, effect-traced **`readDir`-prefetch stage** (§3e, §6 S6),
  now a **planned C-19 extension** rather than a maybe-follow-on — doc 01 scopes the
  target corpus to AOS's own package set, so a mechanism covering our actual
  `readDir` wiring is within the RFC's letter. nixpkgs is additionally favorable
  for the *static* path: `all-packages.nix` is a very large file of literal
  `callPackage ./…` edges, so the same path-literal scan there reaches most of the
  tree without needing the `readDir` stage.

## 3. Design

### 3a. Parse-ahead scheduler

**Trigger and frontier.** On evaluation start from the root file (and, cheaply, on
each genuine `import` adoption), enumerate the file's **path-literal IR nodes**
(literal Path `IrData`), resolve each to a candidate realpath using the same
resolution `import_paths` uses (directory → `default.nix`), and seed them into a
bounded speculation frontier. Walk the frontier breadth-first up to a depth cap:
parsing a speculated file yields *its* path-literal nodes, which become the next
BFS layer. BFS (not DFS) keeps speculation shallow-and-wide, matching "prefetch
the files the evaluator is most likely to reach next."

**Where the work runs.** Reuse the existing L2 pool. Add a third demand-task kind
alongside `Force`/`Coerce` (`parallel_demand.rs:84-98`), e.g.
`DemandTaskKind::Speculate { path }`, published to a **separate, strictly
lower-priority lane** so speculation never displaces real force/coerce work: idle
helpers drain `Speculate` only when their Force/Coerce deque and the shared demand
queue are empty (the park-preflight in `parallel.rs:481-536` is the natural hook —
poll the speculation lane during the pre-park window instead of parking). Under
serial mode (`K == 1`) the scheduler is inert: there is no idle worker to absorb
the work, and stealing time from the one evaluating thread would be a pure loss
(this is the honest limit — speculation is a *many-core* lever, §5).

**What a Speculate task does.** Exactly the isolated-parse half of
`load_and_eval_import_bytes_shared` (`eval_load.rs:210-256`): read bytes → gate by
access policy (§3b) → `parse_bytes_with_symbols(source, SymbolTable::new())` →
`resolve` → `nix_lower` → `annotate_import_ir`, then **store the isolated
artifact** (see 3b/3c) — and stop. It does **not** remap into the live table, does
**not** record an impure-input fingerprint, and does **not** evaluate. Adoption
(remap + eval) still happens later, on the demanding worker, exactly as today.

### 3b. Error quarantine

C-19's non-negotiable rule: a speculative parse/scope/lower failure is **stashed,
not raised**, and re-raised only if the file is genuinely imported, reproducing the
exact error C++ Nix (and our demand path) would produce at that point.

**Where the stash lives.** A new in-process, content-keyed table on the shared
context (peer to the other shared logs in `SharedEvalContext`,
`parallel_demand.rs:412-431`):

```text
speculation: SpeculativeParseStore
  by_file: DashMap<ParseFileKey, SpeculativeOutcome>   // key = realpath + blake3(bytes)
enum SpeculativeOutcome {
    Ready(Box<CachedParse>),         // isolated IR + resolved + facts, unremapped
    Failed(StashedParseError),       // captured parse/scope/lower error, NOT raised
}
```

`ParseFileKey` (`cache/parse/mod.rs:162-191`) already carries exactly
`(realpath, content_hash)`, so a stale speculative artifact (file edited between
speculation and demand) is simply a key miss on demand — the content hash guards
it. First-write-wins on insert, matching the confluent merge discipline the other
shared logs use (`parallel_import.rs:60-84`).

**Interaction with the parse cache's negative results.** The durable parse cache
has *no* negative results: `load_or_parse_bytes` returns `Err(ParseCacheError)`
and writes nothing on a parse failure (`cache/parse/mod.rs:407-413`). That is why
the failure stash must be the **in-memory** `SpeculativeParseStore`, never the
durable cache — persisting a speculative parse error would be both a schema change
and a latent parity hazard (a later run could surface a stored error for a file it
never imports). Successful speculative artifacts *may* be written to the durable
cache (they are pure, content-addressed, identical to what the demand path would
write), which is a free warm-cache win; failures stay ephemeral.

**Adoption / demand wiring.** `load_parse_cached_import` (`eval_import.rs:922`)
gains a first consultation step: look up `ParseFileKey::for_source(realpath,
source)` in `SpeculativeParseStore`.

- `Ready(cached)` → adopt it (remap + eval) exactly as a cache hit; count a
  speculation *hit*.
- `Failed(err)` → re-raise through the identical
  `parse_cache_import_error(argument, argument_span, path, source, err)` mapping
  (`eval_load.rs:6-60`) so the byte-identical `ImportParse`/`ImportScope`/
  `ImportLower` diagnostic and span reproduce — the error the demand path itself
  would have produced.
- miss → today's behavior unchanged.

This keeps the observable-behavior invariant: whether a file was speculated or
parsed on demand changes only *timing* and a hit/miss counter, never a value,
never an error, never the `.drv`.

### 3c. Integration with the prefix-replica symbol/module logs

The worry the brief raises — "parsed modules must intern through the same choke
point; does that serialize away the win?" — is already answered by the existing
design and is why speculation is cheap:

- Speculative parse uses an **isolated** `SymbolTable::new()` and never touches the
  live or shared symbol table. No lock, no choke point, during speculation.
- Interning happens **only at adoption**, on the demanding worker, via
  `remap_cached_import_ir` → `intern_symbol_for_eval`, and only for
  genuinely-new symbols (§1d.2). Adoption is work the demand path does *anyway*
  today; speculation moves the parse/resolve/lower/annotate off the critical path
  and leaves only the remap.
- Modules are published to `SharedModuleRegistry` (`parallel_demand.rs:216-231`)
  at adoption too, under the same append-and-publish discipline — speculation
  never publishes a module (an un-adopted speculative module has no `EvalModuleId`
  and is unreachable by any value).

So the intern choke point does not cap the win: the parallelizable mass
(parse+resolve+lower+annotate) runs entirely in isolated symbol space, and the
only shared-log interaction (remap of new symbols) is a small, demand-time, mostly
lock-free residue.

### 3d. Speculation budget (M-23 knobs)

Decision M-23 leaves aggressiveness open. Proposed knobs (env-gated, matching the
`AOS_NIX_*` convention), all defaulting conservative:

| Knob | Meaning | Default |
|---|---|---|
| `AOS_NIX_SPECULATE` | `off` / `parse` / `compile` | `off` initially; `parse` after S5 |
| `AOS_NIX_SPECULATE_DEPTH` | BFS depth from a demanded file | `2` |
| `AOS_NIX_SPECULATE_INFLIGHT` | max queued+running Speculate tasks | `2 × (K-1)` |
| `AOS_NIX_SPECULATE_MAX_BYTES` | skip candidate files larger than this | e.g. 512 KiB |

`parse` vs `compile`: pre-parse (parse+resolve+lower+annotate to a `CachedParse`)
is cheap and the primary lever; pre-*compile* (JIT tier-up of a speculated file's
hot bodies) is deferred behind `compile` because JIT is disabled under parallel
mode today (`native/mod.rs:788`) and the compiled-body cache is a separate program
(`aos-nix-jit-trap-transfer-differential` in memory). The mis-speculation counter
— files speculated but never genuinely imported — lands next to the existing
demand-pool telemetry in `ParallelDemandPool::finish` (`parallel_demand.rs:657-703`)
and the `AOS_NIX_EVAL_STATS` JSON dump: `speculated`, `speculation_hits`,
`speculation_wasted`, `speculation_bytes_read`. M-23 is tuned by watching
`speculation_wasted / speculated` against helper idle time.

### 3e. `readDir`-driven prefetch (approved C-19 extension)

§2 establishes that the AOS package set is discovered by `builtins.readDir` +
`callPackage (dir + "/${name}")` (`pkgs/default.nix:354-383`), which static
path-literal speculation cannot see. Because doc 01 scopes the evaluator's target
corpus to AOS's own package set (general nixpkgs is a non-goal), a prefetch
mechanism that covers *our* wiring is squarely in scope. This is a **planned,
first-class stage** (§6 S6), framed as a **C-19 extension** with its own
decision-register entry candidate (§8) — the letter of C-19 speaks of "statically
known import edges," and a directory listing is a dynamically-obtained edge set,
so it wants its own decision, not a silent reinterpretation of C-19.

**Mechanism.** When evaluation performs `builtins.readDir dir` (a traced impure
input in the effect lattice, S-23), the returned entry set names a bounded family
of candidate files: the `regular` `.nix` entries and the `directory` entries'
`default.nix`, filtered by the same rules `discoverPackages` applies
(`pkgs/default.nix:358-375`: skip `default.nix`, skip `_`-prefixed). Those
candidates are seeded into the *same* speculation frontier the static scanner
feeds (§3a), producing `Speculate { path }` tasks on the same low-priority lane.
The prefetch fires on the `readDir` result the evaluator *actually* obtained, so
it introduces no new filesystem observation the eval was not already going to make
at the directory level.

**Error quarantine is identical.** A `readDir`-seeded speculative parse/lower
failure is stashed in the same `SpeculativeParseStore` (§3b) and surfaced only if
that file is genuinely `import`/`callPackage`-ed later — a package file with a
syntax error that the selected system variant never instantiates must stay silent,
exactly as under static speculation. Nothing about the seeding source changes the
quarantine discipline: the outcome is keyed by `ParseFileKey` (realpath + content
hash) regardless of how the candidate was discovered.

**Soundness boundary.** The seeding *reads* `readDir`'s result but must not alter
the eval's impure-input trace beyond the `readDir` observation the demand path
already records — i.e. seeding happens *after* the real `readDir` impure-input
fingerprint is recorded, consumes its already-materialized entry list, and adds no
further trace entries (the per-file speculative reads are trace-silent, §7). It
speculates only files *named by that listing*, never a guessed sibling, so it
never reads a path the directory did not actually contain. Access policy gates
each candidate read exactly as in §3b/§7.

**Why it is separated from the static stage.** Static path-literal prefetch (S2)
is pure and needs no effect to fire; `readDir` prefetch (S6) rides an effectful
node and therefore lands only after the static machinery, quarantine, and
telemetry are proven, reusing all three. Keeping them distinct stages keeps the
parity story clean: S2 can be validated with zero effectful surface before S6
introduces the `readDir` seam.

## 4. What this does not cover (explicitly)

- **Computed imports via arbitrary expressions.** `import (fetchGit …)`,
  `import someExpr`, and any path built from a value the evaluator has not yet
  produced are **out of scope** for *both* speculation stages — their targets are
  not knowable without evaluation, and no directory listing names them. Note the
  **`readDir`-driven `callPackage (dir + "/${name}")` package discovery**
  (`pkgs/default.nix:377-383`) is **no longer in this list**: it is covered by the
  `readDir`-prefetch stage (§3e, §6 S6). What remains uncovered is the residue of
  genuinely value-dependent import targets, which is small on the AOS corpus (§2:
  the 4 `import (…)` sites are generated-file imports).
- **Import-from-derivation (IFD).** IFD targets are store paths produced by a build
  that has not run at speculation time; nothing static points at them. IFD is an
  effectful node (S-23 effect lattice) and is never speculated.
- **Cross-file lowering or fusion.** Speculation warms per-file artifacts only; the
  simplifier/inliner (doc 26, task #7) is a separate program.
- **Serial-mode speedup.** With `K == 1` the scheduler is inert by design (§3a).
  Tier-1a's win is a *many-core* win; the serial cold-eval lever is S1's
  decoupling plus the doc-26 front-end compression, not speculation.

## 5. Measurement plan

**Precondition (S0): prove the 25% at HEAD.** No parse/lower timer exists
(`eval_stats.rs` has only `imports_evaluated` and the parse-cache hit/miss
counters, `:50-55,85-89`). Two options, in preference order:

1. **Sampling profile** (no code change): run the AOS package-set instantiation
   under a sampling profiler and attribute on-CPU time to `parse_bytes` /
   `parse_bytes_with_symbols`, `resolve`, `nix_lower`, `annotate_import_ir`. This
   is how the original 25% was obtained and is the fastest re-confirmation.
2. **Opt-in scoped timers** behind `AOS_NIX_EVAL_STATS`: accumulate monotonic
   nanos across the four front-end calls into new stats fields
   (`front_end_parse_nanos`, `_resolve_`, `_lower_`, `_annotate_`), dumped in the
   existing JSON block. Parity-neutral (timing only), and it makes the acceptance
   metric self-measuring. Preferred if the sampling profile is ambiguous. The
   precise file/function/field-level diff for this is pre-written in **Appendix A**
   so S0 is mechanical when the build lane opens.

**Acceptance metric.** Cold wall-clock delta on the two established shapes:

- **zlib** (single realistic package instantiation) — the standard cold
  micro-benchmark; expect a modest delta (few files, little to prefetch).
- **wide-eval** (the full/`--all` package-set instantiation) — the shape
  speculation should actually move, since many independent files are reachable and
  helpers would otherwise idle between demand bursts (the wide corpus is exactly
  where P3b measured helper starvation, `parallel_demand.rs:104-108`).

Report `native_mean` from the `nix-bench` harness at `K ∈ {1, 4}` with
`AOS_NIX_SPECULATE ∈ {off, parse}`, plus `speculation_hits/wasted`. **Hard gate:
`K == 1` and `AOS_NIX_SPECULATE=off` must be byte-identical and
zero-regression** versus the pre-change baseline on every parity shape (the
existing `nix-diff`/`nix-bench` darwin gate and the Linux full-corpus `.drv`
parity gate, per `aos-nix-tier1-live-dispatch` and `aos-nix-phase1-acceptance-gate`
in memory). Speculation earning its keep is measured as a *win at K≥2*; it must
never be a *loss at K=1* or a *divergence anywhere*.

## 6. Staged landing order (parity-gated throughout)

Each stage is independently revertible and gated on byte-identical `.drv` output
with speculation off.

- **S0 — Measurement.** Land the parse/lower timers (Appendix A §A.1) **and** the
  prelude-force-share counters (Appendix A §A.3, task #13) in one commit, run the
  parity battery, then run the measurement itself (one instrumented cold eval,
  `AOS_NIX_EVAL_STATS=1`, release, `pkgs.zlib` + one heavier attr) and record the
  two gate numbers — (1) parse/lower share of cold wall, (2) prelude-force count
  ratio plus the nanos proxy — on tasks #3 and #13. Re-confirm the 25% at HEAD.
  Parity-neutral. *Gate: no behavior change.*

> **SESSION HANDOFF BOUNDARY.** This session implements **S0 only** (above), then
> stops for handoff to another engineer (Codex). **S1 through S6 below are the
> handoff spec** — they are designed here in full but not implemented in this
> session. An implementer picking up S1+ should treat this note (and Appendix A)
> as authoritative and proceed stage-by-stage under the same parity gate.

- **S1 — Decouple serial parse from the live symbol table.** Make the
  isolated-parse+remap path (`load_and_eval_import_bytes_shared`'s parse half) the
  serial default too, replacing the `mem::take` fast path
  (`eval_load.rs:102-186`). This is the enabling refactor: after it, *all* parse
  paths produce an isolated artifact adopted by remap, so a parse can run anywhere.
  **Subtlety to gate hard:** the `mem::take` path grows the live table in
  parser-encounter order; the remap path interns in `ir.symbols.symbols()` order.
  Symbol ids are internal and not `.drv`-observable (attribute ordering is
  lexicographic by bytes via `FlatAttrs`, not by symbol id), so parity should
  hold — but S1's whole risk is this id-assignment reordering, so it ships behind
  the full parity gate and nothing else changes in the same commit. *Gate:
  byte-identical `.drv` on all shapes; watch the serial-cold benchmark for the
  known "clone dominated cold eval" regression the `mem::take` avoided — if
  remap-on-adoption re-introduces it, keep `mem::take` for the serial-no-pool case
  and only unlock decoupling under a pool.*
- **S2 — Parse-ahead scheduler, static edges, pre-parse only, default-off.** Add
  the path-literal frontier, the BFS walk, and the `Speculate` lane on the L2 pool
  (§3a), storing successful artifacts in `SpeculativeParseStore::Ready` and (opt)
  the durable cache. No error quarantine yet: a speculative parse *failure* is
  simply dropped (not stored, not raised) so there is nothing to surface
  incorrectly. Wire `load_parse_cached_import` to consult the `Ready` store.
  *Gate: parity unchanged; `AOS_NIX_SPECULATE=parse` shows K≥4 hits and no
  divergence.*
- **S3 — Error quarantine.** Add `SpeculativeOutcome::Failed` and the
  re-raise-on-demand wiring through `parse_cache_import_error` (§3b). Now a
  speculated file with a syntax error is stored-as-failed and reproduced exactly
  on genuine import. *Gate: a targeted test — speculate a file with a parse error
  that the root eval never imports (must produce no error) and one it does import
  (must produce the identical error/span as demand-path parsing).*
- **S4 — M-23 telemetry + tuning.** Add the mis-speculation counters and the
  budget knobs (§3d); tune depth/inflight against `wasted/idle`. *Gate:
  parity-neutral.*
- **S5 — Default-on (static).** Flip `AOS_NIX_SPECULATE` default to `parse` once
  S2–S4 show a wide-eval win at K≥4 with zero parity divergence and no K=1
  regression. *(`compile`/pre-lower speculation stays off, pending
  JIT-under-parallel, §3d.)*
- **S6 — `readDir`-driven prefetch (C-19 extension).** Add the effectful seam
  (§3e): after a `readDir` records its impure-input fingerprint, seed the filtered
  candidate set into the existing speculation frontier. Reuses S2's frontier/lane,
  S3's quarantine, and S4's telemetry unchanged. Lands its own decision-register
  entry (§8). *Gate: parity-neutral with the seam off; with it on, no divergence on
  the full package-set instantiation (the shape that actually exercises
  `discoverPackages`) and a measurable helper-idle reduction. Add a targeted test:
  a directory containing a syntactically-broken `.nix` that the selected variant
  never instantiates must stay silent, and one that is instantiated must reproduce
  the identical demand-path error.*

## 7. Why speculation is side-effect-free — and the one place it isn't

Speculation is sound because it stops before every observable action of the demand
path:

- **No impure-input recording.** The import fingerprint is recorded in the demand
  path (`record_impure_input_result`, `eval_import.rs:881`), which speculation
  never enters. This matters: appending to the impure-input trace would change the
  force-cache trace and the root-cutoff key (`aos-nix-root-cutoff` in memory), i.e.
  it *would* be observable. Speculation stopping at lower keeps the trace
  identical.
- **No value, no module publication, no error.** An un-adopted speculative module
  has no `EvalModuleId` and is unreachable; a stashed failure is never raised
  unless demanded (§3b).
- **Purity of the artifact.** A parse artifact is a pure function of source bytes
  (`ParseCacheKey::for_source`, `cache/parse/mod.rs:96`); content-hash keying makes
  a stale speculation a harmless miss.

**The one genuine side effect: the filesystem read.** Speculation reads candidate
files ahead of demand. Two obligations follow, and both are load-bearing:

1. **Access policy must gate the speculative read.** The demand path enforces
   `check_filesystem_path_access` before reading (`import_paths`,
   `eval_import.rs:776,789`). A speculative read of a path the eval would refuse is
   not *value*-observable, but it is a real syscall and a sandbox concern, so the
   Speculate task must apply the identical access check and skip disallowed paths.
   In `Restricted`/`Pure` eval modes (`eval_import.rs:282-305` shows the pattern
   for `fetchurl`) speculation must honor the same allow-list.
2. **Only real, named candidates — never a guessed path.** The static stage
   follows only literal Path nodes (content on disk, not effect outputs). The
   `readDir` stage (§3e) follows only files *named by a listing the evaluator
   actually obtained*, seeded after that `readDir`'s impure-input fingerprint is
   recorded, and adds no further trace entries. Neither stage ever speculates a
   store path that is a build output (IFD, §4) or a guessed sibling the source did
   not name.

With those two guards, the *only* externally observable output of speculation is a
warm cache entry and a timing change — the C-19 invariant.

## 8. Open questions and doc-vs-code divergences

1. **"rayon pool" (doc 04 §9.6, doc 13 §5.5.1) vs the real pool — RESOLVED
   (ruling 3).** The docs describe the parallel substrate as "the rayon
   work-stealing pool" (doc 13 §5.5.1 table row, `13-parallel-evaluation.md:573`).
   The implementation is a hand-rolled `std::thread` helper pool with Chase-Lev
   deques and a bespoke demand queue (`parallel_demand.rs:480,572`,
   `parallel_chase_lev.rs`); there is no `rayon` dependency. **Ruling: keep the
   shipped-and-tested hand-rolled substrate; do not adopt rayon.** The doc-13 §5.5.1
   wording fix ("rayon work-stealing" → "hand-rolled `std::thread` + crossbeam
   Chase-Lev work-stealing") is deferred to a batched doc-corrections pass rather
   than churning doc 13 now. Speculation schedules on the actual pool; no behavior
   rides on the word "rayon."
2. **AOS corpus vs C-19's static-edge assumption — RESOLVED (ruling 2).** doc 04
   §9.6 leans on "`import ./foo.nix` with a literal path is a static edge." True,
   but on the AOS corpus the load-bearing edges are `readDir` +
   `callPackage (dir + "/${name}")` (§2), which are *computed*. **Ruling: pursue
   the `readDir`-driven prefetch as a first-class stage (§3e, §6 S6)**, not a
   maybe-follow-on — doc 01 scopes the target corpus to AOS's own package set, so a
   mechanism covering our actual wiring is within the RFC's letter. Remaining open
   item: this wants **its own decision-register entry** (a `readDir` listing is a
   dynamically-obtained edge set, so it should be a named C-19 extension, e.g. a
   new `C-2x`, rather than a silent reinterpretation of C-19). Drafting that entry
   is a doc task to batch with the doc-13 §5.5.1 fix.
3. **S1 symbol-id reordering.** Whether making remap-on-adoption the serial default
   is truly `.drv`-invariant needs the full Linux parity corpus to confirm, not
   just the darwin gate — symbol-id order is internal but the proof that nothing
   leaks it is empirical. If S1 regresses serial-cold wall (the `mem::take`
   clone-avoidance, `eval_load.rs:125-129`), keep `mem::take` for the no-pool case
   and gate decoupling on `self.shared.is_some()`.
4. **Speculation lane vs park-preflight.** §3a proposes draining the Speculate lane
   during the pre-park window (`parallel.rs:481-536`). Whether that hook admits a
   third lane cleanly, or wants a dedicated low-priority Chase-Lev deque per worker,
   is an implementation choice to settle in S2 — it does not affect the design's
   soundness, only its scheduling efficiency.

## Appendix A — S0 parse/lower timer diff-plan (mechanical when the lane opens)

The first implementation increment. It lands the instrumentation for **two**
gates in one pass, so S0 is a single transcription job: (i) the "~25% of cold"
parse/lower claim this note depends on (§A.1), and (ii) the **prelude-force-share**
metric that gates task #6 heap-image snapshots (§A.3, added per the snapshot-design
ruling). All of it is behind `AOS_NIX_EVAL_STATS`, so the default hot path pays
nothing and the K=1/speculate-off parity+performance gate is untouched.
Instrumentation-only: no value, error, or `.drv` changes.

§A.1 adds four monotonic front-end timers to the existing eval-stats surface so no
later stage claims a `%` win without timer evidence.

### A.1 Files and exact edits

1. **`crates/ratchet-oracle/src/eval/tree_walk/outcome.rs` — the `EvalStats`
   struct (`:13347`).** Add four `u64` nanosecond accumulators immediately after
   `imports_evaluated: u64` (`:13408`), matching the surrounding `pub(crate)`
   field convention:

   ```text
   pub(crate) front_end_parse_nanos: u64,      // parse_bytes_with_symbols
   pub(crate) front_end_resolve_nanos: u64,    // resolve / ScopeResolver
   pub(crate) front_end_lower_nanos: u64,      // nix_lower[_with_options]
   pub(crate) front_end_annotate_nanos: u64,   // annotate_import_ir
   ```

   `EvalStats` is merged across workers by `EvalStats::merge_from`
   (`outcome.rs:13720`), which destructures `other` (`imports_evaluated` at
   `:13775`) and `saturating_add`s each field (`:13900`); add the four new fields to
   both the destructure and the add list there, mirroring `imports_evaluated`
   exactly. A `pub const fn` accessor per field (like `imports_evaluated()` at
   `:14066`) is optional but matches the surrounding convention.

2. **`crates/ratchet-oracle/src/eval/tree_walk/eval_stats.rs` — increment
   helpers.** Add four helpers mirroring `increment_imports_evaluated`
   (`:888-890`), each taking a `u64` nanos and `saturating_add`-ing into the
   matching field. Also add the four fields to the outcome-snapshot copy near
   `:85` (where `imports_evaluated: self.stats.imports_evaluated` is copied into
   the public snapshot), if that snapshot enumerates fields explicitly.

3. **`crates/ratchet-oracle/src/eval/tree_walk/eval_load.rs` — the timed call
   sites.** Wrap the four front-end calls in *both* import parse paths. Guard each
   with `self.options.eval_stats_dump()` so no `Instant::now()` is taken when
   stats are off:

   - serial `load_and_eval_import_bytes` (`:131` parse, `:144-147` resolve,
     `:160-164` lower, `:181` annotate);
   - parallel `load_and_eval_import_bytes_shared` (`:210` parse, `:222-226`
     resolve, `:239-243` lower, `:256` annotate).

   Shape (illustrative, per call):

   ```text
   let __t = self.options.eval_stats_dump().then(std::time::Instant::now);
   let parsed = parse_bytes_with_symbols(source, live_symbols)?;
   if let Some(t) = __t { self.add_front_end_parse_nanos(t.elapsed().as_nanos() as u64); }
   ```

   The cache-path parse inside `ParseCache::load_or_parse_bytes`
   (`cache/parse/mod.rs:407-411`) is intentionally **not** timed here: it lives in
   a crate with no `TreeWalk` handle, and the "~25% of cold" target is the
   no-cache cold path these two `eval_load.rs` functions own. If cache-path timing
   is later wanted, thread a `&mut u64` out of `load_parse_cached_import`
   (`eval_import.rs:922`) rather than reaching into the cache crate.

4. **`crates/aos-nix/src/native/eval_stats_dump.rs` — JSON emission.** Add the
   four keys to the `eprintln!` block (after `imports_evaluated`, `:75+`) and to
   the module-doc `text`-fenced example (`:11-51`), keeping key order stable for
   the `NIX_SHOW_STATS`-style diff consumers:

   ```text
   "front_end_parse_nanos":{},"front_end_resolve_nanos":{},
   "front_end_lower_nanos":{},"front_end_annotate_nanos":{},
   ```

### A.2 Verification (when the lane opens)

- `nix develop -c cargo build --manifest-path crates/Cargo.toml --bin aos`, then
  run the AOS package-set instantiation with `AOS_NIX_EVAL_STATS=1` and confirm the
  four keys sum to ≈25% of the measured cold wall (re-confirming the claim at
  `HEAD`).
- Parity/no-regression gate: with `AOS_NIX_EVAL_STATS` **unset**, the `nix-diff` /
  `nix-bench` darwin gate must be byte-identical and within noise of the
  pre-change baseline (the `.then(Instant::now)` guard means zero calls on the hot
  path).
- File-size gate (`tests/source_file_size.rs`): `outcome.rs` is already the
  largest oracle file (14,420 lines) — four field lines do not cross a cap, but
  re-run the gate since it is pre-existing-red on some files (task #9).

### A.3 Prelude-force-share metric (task #6 heap-snapshot gate)

Task #6 (heap-image snapshots, doc 31 §1) pre-forces the prelude scaffolding — the
`lib/` + `stdenv/` graph that is identical across every package — once into a heap
image, so its payoff is bounded by **the fraction of cold-eval work spent forcing
prelude thunks** rather than package-specific thunks. S0 must emit that number.
The mechanic the ruling suggests is sound: **module provenance is known at force
time**, so each force can be attributed to prelude vs package by the owning
module's source path.

**Provenance is available and cheap.** A forced thunk's owning module is
`self.current_module` at the force-accounting site
(`alloc_intern.rs:1904,1917-1918`, the `EvalNodeRef::new(self.current_module, id)`
subject and the `increment_thunks_forced()` call). The module's file path is
`TreeWalkModule.source: Option<ModuleSource>` → `ModuleSource.name`
(`tree_walk.rs:690,777-780`), which is the import realpath. "Prelude" is a path
classification: the realpath lies under the repo `lib/` or `stdenv/` tree (final
prefix set is a config detail — the AOS `lib` graph plus `stdenv/`). To keep the
per-force cost to a single branch, **classify once at module construction**: add
`is_prelude: bool` to `TreeWalkModule`, computed in `TreeWalkModule::new`
(`tree_walk.rs:695`) / `push_module` by testing `source.name` against the prelude
prefixes. Per force then costs one bool read, not a string scan.

**Two counters, one optional wall bucket.** Add to `EvalStats` (`outcome.rs`,
beside the front-end fields), wired through `merge_from` (`:13720`) identically:

```text
pub(crate) prelude_thunks_forced: u64,     // forces whose owning module is prelude
pub(crate) prelude_force_nanos: u64,       // OPTIONAL wall bucket (see caveat)
```

`thunks_forced` already exists, so the **count ratio**
`prelude_thunks_forced / thunks_forced` is the cheap, distortion-free primary
signal — increment `prelude_thunks_forced` next to the existing
`increment_thunks_forced()` (`alloc_intern.rs:1918`) under
`if module_is_prelude(self.current_module)`, gated by `eval_stats_dump()`.

**Wall caveat — read before trusting `prelude_force_nanos`.** A count ratio is not
a wall ratio if prelude thunks are on average cheaper or costlier than package
thunks, and the snapshot payoff is a *wall* saving. Two honest options for the
wall figure, in preference order:

1. **One-off sampling profile with module attribution** (most accurate, no per-force
   overhead): attribute on-CPU force time by the owning module's path prefix. Use
   this figure for the actual task-#6 go/no-go.
2. **`prelude_force_nanos` bracket bucket** (always-available proxy): time the
   `eval_thunk_body` span (`alloc_intern.rs:1927-1938`) and add to the prelude
   bucket when the owning module is prelude. This double-counts nested forces
   (an outer prelude force's span includes inner forces) and adds per-force
   `Instant` overhead, so its **absolute** nanos are inflated and its **ratio**
   against a same-method total-force bucket is the only trustworthy read. Ship it
   only if the sampling profile is unavailable, and label it a proxy.

The count ratio (option-0, always on under the stats flag) is what belongs in the
dump; the wall figure is a measurement, not a shipped counter. Emit
`prelude_thunks_forced` (and, if built, `prelude_force_nanos`) in the same
`eval_stats_dump.rs` JSON block and `text` example as the front-end fields.

**One mechanical check at implementation time.** Confirm `self.current_module` at
`alloc_intern.rs:1917` is the *forced thunk's def-site* module, not the caller's —
the force-cache subject keys on `(self.current_module, id)` (`:1904`), which is
only correct if `current_module` is already the thunk's owning module at that
point, so it almost certainly is; but if a captured-module swap happens inside
`eval_thunk_body` instead, read the thunk's captured module ref for classification.
This is the one-line check that decides the attribution site.

**Gate accounting note for task #6.** The prelude-force *share* is the *ceiling* on
snapshot payoff, not the payoff: the snapshot also pays to load/map the image, and
a warm-parse-cache run already amortizes prelude *parsing* (§1b). So task #6 should
compare `prelude_thunks_forced` share against the snapshot's load cost, using the
front-end timers (§A.1) to separate prelude *parse* savings (already available via
the parse cache) from prelude *force* savings (the snapshot's unique contribution).

