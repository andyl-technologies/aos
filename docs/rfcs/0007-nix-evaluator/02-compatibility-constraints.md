# RFC-0007 - Compatibility Constraints: Byte-Identical Derivations, String Contexts, and the Acceptance Gate

This document specifies the single hardest, most unforgiving requirement that
shapes every other decision in aos-nix: **bug-for-bug output compatibility with
C++ Nix**. It defines exactly what "compatible" means at the byte level, why the
penalty for any divergence is uniquely catastrophic in the ANDYL OS (AOS)
context, which Nix-observable artifacts and hashes are non-negotiable, and how
the differential testing harness becomes the *acceptance gate* that governs
whether aos-nix may ever be turned on.

The thesis of the broader RFC (see
[motivation and goals](01-motivation-and-goals.md)) is that a fast Nix evaluator
is achievable by harvesting the best implementation techniques from GHC,
HotSpot, V8, LuaJIT, Nix itself, and incremental-computation research. None of
those techniques matter if the evaluator produces even one different store path.
This document is therefore the *constraint envelope* inside which all the
performance work in
[architecture overview](03-architecture-overview.md) onward must live. A
technique is only admissible if it is **observably invisible** at the .drv
boundary.

---

## 1. The shape of the contract

### 1.1 What aos-nix replaces, and what it does not

AOS performs two distinct phases that are frequently conflated:

```text
  .nix expression tree                 .drv derivation graph              build outputs
  ────────────────────  ──eval──▶  ───────────────────────  ──build──▶  ──────────────
  parse + lazily force              ATerm files in the store             /nix/store/<h>-<name>
  the expression                    (input/output addressed)            (the actual artifacts)
        ▲                                     ▲                                  ▲
        │                                     │                                  │
   aos-nix OWNS this ────────────────────────┘                                  │
   (eval -> .drv)                                                               │
                                            C++ Nix / the build daemon OWNS this┘
                                            (.drv -> outputs; aos-nix never builds)
```

aos-nix replaces **only** the left arrow: parsing `.nix` files and lazily
evaluating the expression tree into a `.drv` derivation graph. The realisation
of those `.drv` files into build outputs remains the job of the existing Nix
build daemon, driven through `NixCli` in
`crates/aos-core/src/nix/store.rs`. The integration seam is described in
[integration with AOS](14-integration-with-aos.md).

This separation is what makes the compatibility contract *tractable*: we do not
have to reproduce sandboxing, fixed-output rewriting, NAR dumping during builds,
or the binary-cache protocol. We have to reproduce exactly one thing — the
function

```text
  instantiate : (file, attr, args, env) -> set of .drv files + their store paths
```

— such that it is *extensionally indistinguishable* from `nix-instantiate`.

### 1.2 The contract, stated precisely

> For every evaluation input the AOS package set can produce, aos-nix MUST emit
> the **byte-identical** set of `.drv` files at the **byte-identical** store
> paths that C++ Nix emits for the same input, including all transitively
> referenced input derivations, and MUST attach **byte-identical string
> contexts** to every string it hands to `derivationStrict`.

"Byte-identical" is meant literally: a `cmp(1)` of the two `.drv` files returns
no differences, and the two store paths are character-for-character equal. This
is stronger than "semantically equivalent" and far stronger than "produces a
working build". We explain in Section 3 why nothing weaker is acceptable.

### 1.3 Why bug-for-bug, not standards-compatible

Nix has no specification. The reference implementation *is* the specification,
quirks included. Several behaviors that a clean-room implementer would consider
bugs are load-bearing for hash stability:

- The ATerm serialization omits the derivation's own name and relies on it being
  supplied out-of-band, and uses a specific, unspecified quoting and field
  ordering. (See the ATerm format references in Section 8.)
- The store-path hash is a SHA-256 **XOR-folded down to 160 bits**
  (`compressHash`, not a simple truncation), re-encoded in a **custom,
  non-standard base-32 alphabet** that is "not documented nor standardized in
  any way."
- Attribute set iteration order is the order Nix's internal representation
  happens to produce (sorted by interned symbol, with its own collation), and
  that order leaks into the ATerm environment block.
- String context propagation has accreted edge cases (e.g. `builtins.getContext`
  loses the original attrset shape; deep vs. shallow context elements; the
  `!output` and `=drv` context markers) that any compatible implementation must
  reproduce exactly.

We therefore commit to **bug-for-bug** parity. Where C++ Nix does something a
language designer would not, aos-nix does the same thing, and we record the
quirk rather than "fix" it. This mirrors how Snix (the renamed Tvix project)
reuses the C++ Nix language test suite rather than inventing its own semantics,
and slices the derivation/ATerm/store-path logic into the shared `nix-compat`
crate precisely so that the fiddly parts are written once and tested against the
reference.

---

## 2. The Nix-observable surface that MUST match exactly

It helps to draw a hard line between the parts of aos-nix that are **internal**
(free to be as exotic as performance demands) and the parts that are
**observable** by Nix and therefore frozen. Everything in
[value representation](05-value-representation.md),
[memory management](06-memory-management-and-gc.md),
[laziness analyses](07-laziness-and-whole-program-analyses.md), and
[execution tiers](08-execution-tiers-and-cranelift.md) is internal. The
following table enumerates the observable surface. If a value appears in this
table, a single wrong byte is a release blocker.

| Observable artifact | Definition | Hash / format | Frozen because |
|---|---|---|---|
| Output store path | `/nix/store/<32-char-b32>-<name>` for each derivation output | trunc-160 of SHA-256, custom base-32 | Any change -> cache miss -> rebuild |
| `.drv` store path | store path of the derivation file itself | "text" content-addressing: SHA-256 of ATerm | Names every node in the graph |
| `.drv` file contents | the ATerm-serialized `Derivation` | exact ATerm bytes | Hashed to produce the `.drv` path |
| Input-derivation refs | `inputDrvs` map: drv path -> output names | embedded in ATerm | Wrong refs -> wrong drv hash |
| Fixed-output hashes | `outputHash`, `outputHashAlgo`, `outputHashMode` | as written by the expression | Defines FOD identity |
| String contexts | per-string set of store-path dependencies | interned context elements | Drives `inputDrvs`/`inputSrcs` |
| Source store paths | paths added by `builtins.path`/`./.` coercion | NAR SHA-256 hash | Appear in `inputSrcs` |
| `nix-instantiate` stdout | the printed `.drv` path(s) | text | The harness diffs this |
| Eval errors (where checked) | error class + message for guarded cases | text (best-effort) | Some packages assert on them |

Everything **not** in this table — thunk layout, GC strategy, hidden classes,
inline-cache state, Cranelift IR, the incremental cache keys (which use xxh3 and
blake3, never SHA-256) — is invisible to Nix and may change freely between
aos-nix versions. This is the crucial degree of freedom that lets us be
aggressive everywhere else.

---

## 3. Why divergence is catastrophic *here* specifically

Every Nix user pays a penalty for store-path divergence: a different store path
is a different cache key, so anything that depended on the old path misses cache
and must be re-evaluated or rebuilt. In a normal deployment that is annoying. In
AOS it is **catastrophic**, and the reason is structural to this repository.

AOS is a hermetic, from-source Linux distribution. As the project memory and
[CLAUDE.md](../../../CLAUDE.md) record, *nothing* is taken from upstream
nixpkgs: the entire toolchain is bootstrapped from `hex0` through GNU Mes, TinyCC,
a GCC toolchain ladder (gcc3.4 -> gcc14), glibc, binutils, and onward to
multi-version LLVM, Rust (mrustc -> rustc 1.93), Bazel, the full OpenJDK 8->25
chain, and so on. These are some of the longest, most expensive build closures
in existence — the GCC ladder and the JDK chain each take hours, and they sit at
the *root* of the dependency DAG.

Now consider the failure mode:

```text
  aos-nix emits one wrong byte in glibc's .drv
          │
          ▼
  glibc gets a different output store path
          │
          ▼
  every derivation with glibc in its closure (i.e. essentially ALL of them)
  gets different inputDrvs -> different .drv hash -> different output path
          │
          ▼
  total cache miss across the ENTIRE distribution
          │
          ▼
  the from-source toolchain rebuilds from hex0 upward — hours to days of compute
```

The store-path graph is *Merkle-structured*: a change low in the DAG fans out to
everything above it. A single byte of divergence in a foundational derivation
does not cost one rebuild; it costs the **whole distribution**. This is why the
compatibility constraint cannot be relaxed "just for the rare edge case" — in a
from-source monorepo the rare edge case in a base package is the most expensive
possible event.

This asymmetry also explains the project's risk posture (see
[roadmap and risks](17-roadmap-and-risks.md)): the dominant risk is not that
aos-nix is slow, but that it is *subtly wrong*. A slow-but-correct evaluator
wastes minutes; a fast-but-divergent evaluator wastes machine-weeks and erodes
trust in the cache. Therefore the entire program is governed by a **measure-first,
correctness-first, default-off** discipline. aos-nix is never the default until
the differential harness (Section 7) is green across the full closure, and even
then `NixCli` remains a permanent fallback.

---

## 4. Store paths and derivation hashing: the exact algorithm we must reproduce

Compatibility lives or dies on reproducing two hashing pipelines exactly. We
restate them here so the constraint is concrete and so the implementation in
[derivation and store compatibility](11-derivation-and-store-compatibility.md)
has an authoritative reference. The mechanics below are confirmed against the Nix
reference manual and the `nix-compat` documentation (Section 8).

### 4.1 The store-path fingerprint

Every store path is `/nix/store/<digest>-<name>`, where `<digest>` is a
32-character string in Nix's custom base-32 alphabet. The digest is computed
from a **fingerprint string** of the canonical form:

```text
  <type>:<comma-separated-refs>:sha256:<inner-hash-hex>:/nix/store:<name>
```

The pipeline, in the exact order Nix performs it:

```text
  fingerprint string
        │  SHA-256
        ▼
  32-byte digest
        │  truncate to first 160 bits (20 bytes), folding via XOR
        ▼
  20-byte compressed digest
        │  Nix custom base-32 encode (NOT RFC 4648)
        ▼
  32-character path digest
```

Two details are individually sufficient to break compatibility if gotten wrong:

1. **160-bit truncation.** Nix does not use the full SHA-256. It compresses the
   32-byte hash down to 20 bytes (`compressHash`), then base-32 encodes that.
2. **Custom base-32 alphabet.** Nix uses the alphabet
   `0123456789abcdfghijklmnpqrsvwxyz` (note the omitted letters `e o u t`) and
   encodes from the **most significant** end in its own bit order. Using RFC
   4648 base-32, or even the same alphabet with standard bit packing, yields a
   different string.

The `<type>` and `<refs>` fields vary by store-object kind:

- **Source paths** (`builtins.path`, path literals coerced to strings):
  `type = "source"`, inner hash is the SHA-256 of the NAR serialization of the
  file/tree, and refs are the path's own self-references.
- **Output paths of input-addressed derivations**: `type = "output:<name>"`,
  and the inner hash is derived from the derivation's ATerm (Section 4.3).
- **Fixed-output derivations (FODs)**: a `fixed:out:<algo>:<hash>:` recipe is
  hashed to produce the path; FODs are *referenced by* input-addressed store
  paths even though their content is content-addressed.

aos-nix reuses the `nix-compat` crate (from the Snix project, pinned to a git
rev) for all of this rather than reimplementing it, because this is exactly the
class of code where a clean-room reimplementation accumulates subtle drift. See
the integration plan in
[derivation and store compatibility](11-derivation-and-store-compatibility.md).

### 4.2 The ATerm serialization

The `.drv` file is the ATerm serialization of the `Derivation` structure. ATerm
here is a specific textual encoding with the shape:

```text
  Derive(
    [(outName, path, hashAlgo, hash), ...],     # outputs, sorted by output name
    [(drvPath, [outName, ...]), ...],           # inputDrvs, sorted by drv path
    [srcPath, ...],                             # inputSrcs, sorted
    platform,                                   # e.g. "x86_64-linux"
    builder,                                    # the builder executable path
    [arg, ...],                                 # builder args
    [(key, value), ...]                         # env, sorted by key
  )
```

The serialization is exacting in ways that are easy to get wrong:

- **String quoting.** ATerm strings are double-quoted with a specific escape set
  (`\"`, `\\`, `\n`, `\r`, `\t`). Any deviation in which characters are escaped,
  or how, changes the bytes.
- **Field ordering.** Outputs are ordered by output name; `inputDrvs` by drv
  path; environment by key. The ordering is part of the format, not an
  implementation accident we may reorder for cache friendliness.
- **The name is omitted from the ATerm** and supplied out-of-band — the
  serialized form deliberately does not contain the derivation's name, on the
  assumption that the store path carries it.

aos-nix uses `nix-compat`'s ATerm writer, which has unit tests against C++ Nix
output and includes an ATerm *parser* — useful for the harness's structural diff
mode in Section 7.

### 4.3 The "text" content-addressing of the `.drv` itself

Two distinct hashes are in play here and must not be confused:

The **`.drv` file's own store path** uses `"text"` content-addressing: its inner
hash is the SHA-256 of the final ATerm bytes, and its references field lists the
`inputDrvs` paths and `inputSrcs`.

The **output paths** of an input-addressed derivation are computed first, by the
well-known masked-derivation procedure:

1. Serialize the derivation with each output path field left as the empty
   string (the "derivation modulo" / masked form).
2. SHA-256 that masked ATerm, hex-encode it, and feed it into the
   `output:<name>:sha256:<inner>:/nix/store:<name>` fingerprint of Section 4.1 to
   get each output path.
3. Substitute the now-known output paths back into the derivation and
   re-serialize; the result is the final `.drv` bytes, which are then
   `"text"`-hashed to produce the `.drv` store path.

Every one of these steps uses **SHA-256**, dictated by the Nix on-disk format.
This is non-negotiable and orthogonal to aos-nix's *internal* hashing policy:
the incremental cache uses xxh3 for hot in-process hashing and blake3 for the
durable content-addressed cache (see
[incremental evaluation cache](12-incremental-evaluation-cache.md)), but **SHA-256
is used wherever the result is observed by Nix as a drv or store hash**, with zero
exceptions. Mixing these up — e.g. blake3-hashing a fingerprint that Nix expects
to be SHA-256 — produces a different path and is the canonical way to fail this
contract.

---

## 5. String contexts: the part most clean-room implementations get wrong

String contexts are where the dependency graph is actually *discovered* during
evaluation, and they are the most common source of subtle divergence because
they are an implicit, side-band data structure threaded through ordinary string
operations.

### 5.1 What a string context is

In Nix every string value carries, alongside its character data, a **context**:
a set of references to store paths that the string "mentions." Interpolating a
derivation into a string adds that derivation to the context; interpolating a
source path adds that path. The context is what `derivationStrict` reads to
populate a derivation's `inputDrvs` and `inputSrcs`. Without correct contexts the
serialized `.drv` will have the wrong inputs and therefore the wrong hash —
*even if every visible character of every string is correct*.

Context elements come in distinct flavors that must be preserved exactly:

```text
  plain store path           ->  the path itself (an inputSrc)
  derivation output (=drv)    ->  "this string depends on output `out` of <drv>"
  all-outputs / deep (!out)   ->  output-specific or whole-closure dependency
```

Determinate Systems' and the Nix manuals' descriptions of string context
(Section 8) enumerate these element kinds; aos-nix must round-trip all of them,
including the awkward case where `builtins.getContext` exposes the context as an
attrset keyed by drv path — a representation aos-nix must be able to produce and
re-consume byte-for-byte.

### 5.2 How aos-nix represents and propagates context

Internally (this part is *not* observable, so we optimize it), a context is an
**interned, copy-on-write bitset of store-path identifiers**, as introduced in
[value representation](05-value-representation.md):

```rust
/// A string's context: the set of store paths it transitively mentions.
///
/// Stored as a copy-on-write bitset over interned store-path ids so that the
/// overwhelmingly common case (a string with empty or singleton context) costs
/// no allocation, and `s1 + s2` is a bitset union over shared, immutable backing
/// storage. The representation is internal; what `derivationStrict` observes is
/// the canonical set of context *elements*, which must match C++ Nix exactly.
#[derive(Clone)]
struct StringContext {
    /// `None` is the empty context (the common case: literal strings).
    elems: Option<Arc<ContextBitset>>,
}
```

The operations that must propagate context, and the rule for each:

| Operation | Context rule |
|---|---|
| `a + b` (string concat) | union of `a` and `b` contexts |
| `"${x}..."` interpolation | union of all interpolated parts' contexts |
| `builtins.toString drv` | adds the drv's `=drv`/output element |
| `builtins.substring` / `replaceStrings` | preserves (does not drop) context |
| `builtins.unsafeDiscardStringContext` | clears context (must clear, exactly) |
| `builtins.getContext` / `appendContext` | round-trip the attrset form |
| path coercion (`./foo`) | adds the source path after NAR-hashing |

Because Nix values (and thus contexts) are **immutable**, the COW bitset is sound
and union is cheap — this is one of the many places where Nix's purity makes an
optimization that would be unsound in an imperative language total and safe here
(see the synthesis thesis in
[architecture overview](03-architecture-overview.md)). The same immutability lets
us **hash-cons** identical contexts so that the thousands of strings carrying the
exact same "depends on glibc" context share one allocation and compare by pointer.

### 5.3 Why this is the high-risk area

The visible characters of a string are easy to get right; the *invisible* context
is not. A classic divergence is dropping context across an operation Nix happens
to preserve it across (e.g. `substring`), which silently removes an input from a
downstream `.drv`, changing its hash. Because context bugs are invisible in the
string's printed value, they are *only* caught by diffing the resulting `.drv` —
which is exactly why the acceptance gate diffs `.drv` files and not eval output
strings. Section 7's harness is the only reliable detector for this class.

---

## 6. The admissibility rule for every optimization in this RFC

The compatibility contract is not merely a testing requirement; it is a *design
filter* applied to every technique elsewhere in the RFC. We state it as a rule:

> **Admissibility rule.** A technique is admissible iff it cannot change any
> artifact in the Section 2 observable table for any input. Equivalently: it must
> be a behavior-preserving transformation of the *function* `instantiate`,
> observable only through the internal columns.

Worked examples, each cross-referencing where the technique lives:

- **Hash-consing / maximal sharing**
  ([value representation](05-value-representation.md)). Admissible: deduplicating
  structurally-equal immutable values changes pointer identity (internal) but not
  value semantics. Caveat: `builtins` that can observe identity must not be given
  a reference-equality fast path that disagrees with Nix's structural `==`.

- **Strictness / demand analysis + worker-wrapper**
  ([laziness analyses](07-laziness-and-whole-program-analyses.md)). Admissible
  *only* for bindings provably always forced. Forcing a thunk that Nix would
  never force can turn a non-error into an error (e.g. `throw` in an unused
  attr), which is observable. The analysis must be **sound and conservative**:
  when in doubt, stay lazy. Nix's purity makes the analysis sound where it would
  be partial in an effectful language, but evaluation *errors* are an observable
  effect and bound the eagerness we may apply.

- **Escape analysis + scalar replacement** (HotSpot-style,
  [laziness analyses](07-laziness-and-whole-program-analyses.md)). Admissible:
  eliminating allocations for non-escaping attrsets is invisible — provided the
  scalar-replaced set never reaches `derivationStrict`, `getContext`, or any
  primop that would serialize or hash it. The escape analysis must treat those
  primops as escape points.

- **Hidden classes + inline caches** (V8-style,
  [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)).
  Admissible: shapes are an access-acceleration structure. The one hard
  constraint they inherit is **deterministic iteration order** — attr order leaks
  into the ATerm environment block, so the shape system must reproduce Nix's
  symbol-collation order exactly, not merely *an* order.

- **Cranelift tiering, deopt, OSR**
  ([execution tiers](08-execution-tiers-and-cranelift.md)). Admissible: a JIT is
  a faster way to run the same semantics. Correctness is anchored by the
  tree-walk **oracle** tier (Section 7.4): the optimized tiers must produce the
  oracle's result or it is a bug, and deoptimization falls back to the oracle.

- **Incremental early-cutoff cache**
  ([incremental evaluation cache](12-incremental-evaluation-cache.md)).
  Admissible *because Nix is pure*: a memoized result keyed on
  expression-hash + environment-hash is reusable iff inputs are unchanged. The
  cache keys use xxh3/blake3 (internal); the *value* it reproduces — the `.drv` —
  is byte-identical to a fresh eval. The gate runs both with and without the
  cache populated to prove the cache never changes the answer.

- **Parallel forcing** ([parallel evaluation](13-parallel-evaluation.md)).
  Admissible: a pure language makes evaluation order non-observable for *results*.
  The subtlety is error *reporting* — which of two failing branches surfaces its
  error can depend on scheduling. Where Nix's order is observable, the parallel
  scheduler must match it or the coarse top-level-only parallelism is used.

The pattern is uniform: **purity and immutability are the enabling preconditions,
and the observable table is the boundary.** Any technique that respects the
boundary is fair game; any that crosses it is rejected no matter how fast.

---

## 7. The acceptance gate: the differential .drv-diff harness

Compatibility is not a claim we get to assert; it is a property the harness
*demonstrates* on every commit. The harness is the formal **acceptance gate** for
the whole project. It is described operationally in
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md);
here we specify what it must prove and why its design follows from Sections 2–5.

### 7.1 What the gate proves

```text
  for each (file, attr) in the AOS package set closure:
      drv_ref  = nix-instantiate <file> -A <attr>      # C++ Nix, the oracle
      drv_aos  = aos-nix instantiate <file> -A <attr>  # the candidate
      assert  drv_aos.path  == drv_ref.path            # store-path equality
      assert  bytes(drv_aos) == bytes(drv_ref)         # ATerm byte equality
      recurse over inputDrvs                            # the WHOLE closure
  GATE PASSES iff every node in every closure matches.
```

The gate is **closure-complete**: it does not stop at the top-level `.drv` but
walks `inputDrvs` to the leaves, because (Section 3) a divergence deep in the
graph is the expensive one. Passing on `hello` proves nothing; the gate is the
full AOS package set, including the foundational toolchain derivations.

### 7.2 Why diff `.drv` files, not eval output

Two evaluators could print the same store path while disagreeing on the `.drv`
contents (impossible if the path is derived from the contents, but a useful
defense-in-depth check) — and, more importantly, a string-context bug (Section 5)
is invisible in printed values yet changes the `.drv`. Diffing the serialized
ATerm bytes is the *only* check that catches context divergence, ordering
divergence, quoting divergence, and FOD-hash divergence in one pass. The harness
therefore compares **bytes**, and offers a structural mode (using `nix-compat`'s
ATerm parser) that, on a byte mismatch, parses both sides and reports the first
differing field — turning "one byte off somewhere in glibc.drv" into "inputDrvs
entry 17 differs."

### 7.3 Three diff modes

| Mode | Compares | Use |
|---|---|---|
| Path diff | the printed store path(s) | fastest triage; first signal |
| Byte diff | `cmp` of `.drv` bytes | the authoritative gate check |
| Structural diff | parsed ATerm field-by-field | root-causes a byte mismatch |

A structural diff that reports "identical fields" while bytes differ localizes
the bug to serialization (quoting/ordering); a structural diff that reports a
differing `inputDrvs` localizes it to evaluation or string context. This makes
the long tail of divergence (the dominant risk in
[roadmap and risks](17-roadmap-and-risks.md)) tractable to chase down.

### 7.4 The tree-walk oracle as a second, internal differential check

Beyond diffing against C++ Nix, aos-nix maintains an *internal* differential
check: the tier-0 tree-walking interpreter is the **correctness oracle**
([execution tiers](08-execution-tiers-and-cranelift.md)). In test and fuzzing
configurations, any thunk's optimized-tier result is checked against the
oracle's. This catches JIT/analysis bugs *before* they reach the .drv boundary
and gives a debuggable reference when a Cranelift-tier result diverges. The
oracle is also the tier kept under miri and sanitizer CI, since the optimized
tiers necessarily use `unsafe` (NaN-boxing, raw heap, JIT fn-ptr calls) that
those tools cannot follow — see the unsafe policy in
[integration with AOS](14-integration-with-aos.md).

### 7.5 Conformance suite reuse

In addition to the AOS-specific gate, aos-nix runs the **C++ Nix language
conformance test suite**, as Snix/Tvix does. These tests pin pure-language
semantics (operators, `builtins`, coercions, error cases) independent of the AOS
package set, and catch regressions in corners the AOS packages happen not to
exercise. The two suites are complementary: conformance tests guard the language;
the .drv-diff gate guards the *output*.

### 7.6 The gating rule (default-off until green)

The harness result drives a single operational rule, enforced through the
`AOS_NIX_NATIVE` env gate in
[integration with AOS](14-integration-with-aos.md):

```text
  if differential_gate(full_AOS_closure) == ALL_MATCH:
      aos-nix MAY be enabled (AOS_NIX_NATIVE=1) for those inputs
  else:
      aos-nix stays OFF by default; NixCli (subprocess) is used
  NixCli remains a permanent fallback regardless.
```

There is no "mostly passing" state in which aos-nix becomes the default. Because
the cost of a single foundational divergence is the whole distribution
(Section 3), the gate is **all-or-nothing for the default-on decision**, even
while aos-nix is used opportunistically (and double-checked against `NixCli`)
during development. This is the concrete mechanism by which the measure-first,
correctness-first posture of [motivation and goals](01-motivation-and-goals.md)
is enforced rather than merely intended.

---

## 8. Open questions and known sharp edges

These are explicitly *not* resolved by this document and are flagged for the
implementation phases:

1. **Custom base-32 endianness corner.** The exact bit-folding of `compressHash`
   (160-bit truncation by XOR-folding) and the MSB-first base-32 emission must be
   taken from `nix-compat`/C++ Nix verbatim; we do not reimplement it. **Open:**
   confirm the pinned `nix-compat` rev matches the C++ Nix version AOS builds
   against, since the format "is subject to change for derivation types which are
   not yet stable" (notably dynamic / CA derivations).

2. **CA-derivations and dynamic derivations.** Content-addressed derivations
   enable build-layer early cutoff and tie into AOS RFC-0005's realisation graph
   (see [derivation and store compatibility](11-derivation-and-store-compatibility.md)).
   Their ATerm encoding is explicitly the "not yet stable" part of the format.
   **Open:** decide whether the first acceptance gate scopes to input-addressed
   derivations only (the bulk of the AOS toolchain) and defers CA-derivation
   parity to a later phase.

3. **`nix-compat` / Snix API instability.** The crate's CLI and APIs are
   explicitly unstable, and the project disclaims real-world performance
   relevance and defers optimization "until nixpkgs-correct." **Mitigation:** pin
   a git rev, vendor as needed, and expect to contribute fixes upstream. **Open:**
   how much of `nix-compat` we vendor vs. depend on directly.

4. **Error-message parity.** Some AOS expressions (and some conformance tests)
   assert on *which* error occurs and sometimes its text. Full byte-parity of
   error messages is a non-goal for the first gate (messages are not Merkle
   inputs), but **error *class*** parity for guarded cases is in scope. **Open:**
   enumerate the AOS packages that assert on error text and decide per-case.

5. **Iteration-order edge cases.** Reproducing Nix's symbol-collation order for
   attribute sets (which leaks into the ATerm env block) requires matching its
   interning/sort exactly, including non-ASCII keys.
   [Attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)
   owns this; flagged here because it is an observable-surface dependency.

---

## 9. Summary

The compatibility contract is the gravitational center of RFC-0007. aos-nix may
be as exotic as it likes internally — NaN-boxed values, bump-arena and
generational GC, hidden classes, Cranelift tiers, an incremental early-cutoff
cache, parallel forcing — but at the `.drv` boundary it must be **byte-identical
to C++ Nix**: identical store paths (trunc-160 SHA-256 in Nix's custom base-32),
identical ATerm bytes, identical string contexts, identical input-derivation
graphs. The penalty for divergence in AOS is uniquely severe because the
Merkle-structured store graph fans a single wrong byte in a foundational
derivation out into a full from-source rebuild of the distribution. The
**differential .drv-diff harness over the entire AOS package-set closure is the
acceptance gate**, complemented by the C++ Nix conformance suite and an internal
tree-walk oracle; aos-nix stays default-off behind `AOS_NIX_NATIVE`, with
`NixCli` as a permanent fallback, until that gate is green end to end. Every
optimization in the rest of this RFC is admitted only if it leaves that boundary
observably untouched.

---

## References

- Nix Reference Manual — Derivation "ATerm" file format:
  <https://nix.dev/manual/nix/2.33/protocols/derivation-aterm>
- Nix Reference Manual — Store Derivation and Deriving Path:
  <https://nix.dev/manual/nix/2.34/store/derivation/>
- Nix Reference Manual — String context:
  <https://nix.dev/manual/nix/2.33/language/string-context>
- Determinate Nix Manual — String context (context element kinds):
  <https://manual.determinate.systems/language/string-context.html>
- Nix Reference Manual — `nix-hash` (160-bit truncation, base-32):
  <https://nixos.org/manual/nix/stable/command-ref/nix-hash>
- Nix Pill 18 — Nix store paths (fingerprint string, custom base-32):
  <http://lethalman.blogspot.com/2015/01/nix-pill-18-nix-store-paths.html>
- Farid Zakaria — "What's in a Nix store path":
  <https://fzakaria.com/2025/03/28/what-s-in-a-nix-store-path>
- Max Bernstein — "Nix derivations by hand, without guessing":
  <https://bernsteinbear.com/blog/nix-by-hand/>
- `nix-compat::derivation` (ATerm serialization, output-path calculation) — Rust docs:
  <https://docs.tvix.dev/rust/nix_compat/derivation/struct.Derivation.html>
- TVL blog — Tvix status (derivation/ATerm sliced into `nix-compat`, test-suite reuse):
  <https://tvl.fyi/blog/tvix-update-february-24>
- devenv — "Introduce Snix evaluation" (Tvix -> Snix rename, adoption):
  <https://github.com/cachix/devenv/issues/1548>
- NixOS/nix issue #4677 — "More context in context string" (`getContext` limitations):
  <https://github.com/NixOS/nix/issues/4677>
