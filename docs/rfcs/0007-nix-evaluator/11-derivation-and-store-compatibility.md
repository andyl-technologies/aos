# RFC-0007 - Derivation and Store Compatibility

> Part of the RFC-0007 documentation set for **aos-nix**, a state-of-the-art Nix
> evaluator written in Rust. This document covers the *output boundary* of the
> evaluator: how an evaluated Nix expression is turned into a `.drv` store
> derivation, how output store paths are computed, how string contexts thread
> dependency information through the language, and why every byte of that
> machinery must match C++ Nix exactly. See [motivation and goals](01-motivation-and-goals.md)
> for why this boundary exists, and [compatibility constraints](02-compatibility-constraints.md)
> for the formal acceptance gate this document operationalizes.

---

## 1. Why this document is the load-bearing wall

Every other document in this set is about *going fast*: NaN-boxed values
([value representation](05-value-representation.md)), a precise generational GC
([memory management](06-memory-management-and-gc.md)), strictness analysis
([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)),
hidden classes ([attribute sets](09-attribute-sets-hidden-classes-and-inline-caches.md)),
Cranelift tiering ([execution tiers](08-execution-tiers-and-cranelift.md)), and a
demand-driven incremental cache ([incremental evaluation cache](12-incremental-evaluation-cache.md)).
All of that is *worthless* — actively harmful, in fact — if the derivation we
emit at the end differs from C++ Nix by a single byte.

The reason is structural to how AOS works, and it is worth restating with
precision because it justifies the entire compatibility posture of this RFC.

AOS is a hermetic, from-source distribution. Its store paths are
**input-addressed**: a derivation's output path is a SHA-256 hash of the
derivation that produces it, which transitively encodes the hash of every input
derivation, back to the bootstrap seed. The store path *is* the cache key. There
is no separate "is this cached?" question; the path's existence in the store (or
in the Attic binary cache, see [incremental evaluation cache](12-incremental-evaluation-cache.md))
*is* the answer.

This produces a brutal failure mode that has no analogue in a normal compiler:

```text
  aos-nix emits a .drv that differs from C++ Nix by one byte
        │
        ▼
  the .drv store path changes  (drv path = hash of ATerm text)
        │
        ▼
  every output path derived from it changes  (output path = hash of drv)
        │
        ▼
  every downstream derivation that referenced those outputs changes
        │
        ▼
  cache miss on the ENTIRE transitive closure
        │
        ▼
  AOS rebuilds the from-source toolchain: gcc, glibc, binutils,
  the GCC ladder, Rust bootstrap, Java chain, Bazel, LLVM ...
        │
        ▼
  hours-to-days of wall time, on every developer machine and CI runner,
  for a one-byte serialization bug
```

A normal optimizing compiler that miscompiles produces a *wrong program*; you
notice, you file a bug, you work around it. An evaluator that mis-serializes a
derivation produces a *different but valid* program that is simply not the one
anyone has built before — so it silently detonates the cache. The cost is not a
crash; it is a catastrophic, *correct-looking* rebuild.

Therefore the contract for this layer is not "compatible." It is
**bug-for-bug, byte-for-byte identical**. We replicate C++ Nix's serialization,
its attribute ordering, its string escaping, its hashing — including any
behavior a purist would call a wart — because the wart is part of the wire
format. This is the same discipline a TLS or a Git reimplementation lives
under: the format is defined by the reference implementation's output, not by a
prose spec, and the prose spec is at best advisory.

This document is the contract. The differential harness in
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
is the enforcement.

---

## 2. The eval/build boundary, precisely

A persistent source of confusion (addressed up front because it scopes
everything below): **aos-nix does not build anything.** Nix has two phases that
people conflate:

| Phase | Input | Output | What does it | aos-nix? |
|-------|-------|--------|--------------|----------|
| **Evaluation** (instantiation) | `.nix` files + CLI attr | a graph of `.drv` files in the store | parse, lazily reduce the expression tree, call `derivationStrict`, serialize ATerm, hash, write `.drv` | **YES — this is the whole crate** |
| **Realisation** (building) | a `.drv` path | output store paths populated with build artifacts | run the builder in a sandbox, hash outputs, register paths | **NO — real Nix still does this** |

aos-nix attacks *evaluation* only. The deliverable of evaluation is a set of
`.drv` files and the top-level derivation path(s). `nix-build` / `nix-store
--realise` then take those `.drv` files and run them. The
[integration with AOS](14-integration-with-aos.md) document describes the
`NixEval` trait whose `instantiate(file, attr) -> DrvPath` method is exactly
this boundary; `aos-core`'s existing `NixCli` (in
`crates/aos-core/src/nix/store.rs`) shells out to `nix-instantiate` today, and
`NixNative` replaces *only that call*.

The consequence for this document: the single artifact that must be byte-perfect
is the `.drv` file (and, transitively, the store paths it names). We do not need
to reproduce NAR serialization of build *outputs* (Nix does that during
realisation), but we *do* need NAR/store-path hashing for `builtins.path`,
`builtins.filterSource`, fixed-output `outputHash` resolution, and
`builtins.toFile` — i.e. wherever *evaluation* must compute a store path. That
distinction maps directly onto which `nix-compat` modules we depend on (§7).

---

## 3. The store derivation: what `derivationStrict` produces

The Nix language exposes `builtins.derivation`, but that is a thin
`derivation.nix` wrapper in `<nix>/corepkgs` around the *real* primop,
`builtins.derivationStrict`. Our job in §5 of the
[primops and runtime ABI](10-primops-and-runtime-abi.md) document is to register
`derivationStrict` as a runtime symbol; *this* document defines what it must do.

A store derivation, once serialized, is the `Derive(...)` ATerm tuple. The
`nix-compat` crate (from the Snix project — see §7) models it as a struct with
seven fields, which is the exact shape we must populate:

```rust
/// The in-memory model of a Nix store derivation, mirroring
/// `nix_compat::derivation::Derivation`. Field order here is documentary;
/// the *serialization* order is fixed by ATerm (see §4) and is what matters
/// for byte-identity.
pub struct Derivation {
    /// Output name -> Output. For a normal derivation the canonical output
    /// is named "out"; multi-output derivations add "dev", "lib", "man", ...
    pub outputs: BTreeMap<String, Output>,

    /// Plain store paths that are direct inputs (e.g. a `builtins.path`
    /// result, a `toFile` result) and are NOT themselves derivations.
    pub input_sources: BTreeSet<StorePath>,

    /// drv-path -> set of output names consumed from that input derivation.
    /// e.g. `{ "/nix/store/…-foo.drv": {"out", "dev"} }`.
    pub input_derivations: BTreeMap<StorePath, BTreeSet<String>>,

    /// The `system` string, e.g. "x86_64-linux".
    pub system: String,

    /// The builder executable path.
    pub builder: String,

    /// argv for the builder (the `args` derivation attribute).
    pub arguments: Vec<String>,

    /// The build-time environment. Values are byte strings (BString),
    /// because Nix env values are not guaranteed UTF-8.
    pub environment: BTreeMap<String, BString>,
}

pub struct Output {
    /// The output store path, EMPTY for content-addressed (floating) outputs
    /// until they are resolved; populated for input-addressed outputs.
    pub path: Option<StorePath>,
    /// Present for fixed-output / content-addressed outputs: the hashing
    /// method (flat vs. recursive/NAR) and algorithm + digest.
    pub ca_hash: Option<CaHash>,
}
```

Two field choices in `nix-compat` are not incidental and we inherit them:

* **`environment` values are `BString`, not `String`.** Nix derivation
  environment values can contain arbitrary bytes (a `builtins.toFile` body, a
  patch with non-UTF-8 content coerced into a string). Forcing UTF-8 here would
  reject valid derivations or — worse — re-encode and change the hash. Our
  [value representation](05-value-representation.md) string type is therefore a
  byte string with an optional UTF-8 validity flag, and it must round-trip
  arbitrary bytes into `environment` losslessly.

* **`outputs`, `input_sources`, `input_derivations` are sorted containers.**
  ATerm output for these is emitted in sorted order. This is not cosmetic: it is
  part of the hashed bytes. §6 ("deterministic ordering") is where this becomes
  the single highest-risk correctness concern.

### 3.1 The `derivationStrict` algorithm, step by step

`derivationStrict` receives a single attribute set argument. The canonical C++
behavior — which we must reproduce — is:

1. **Force the argument to WHNF** and require it to be an attrset (it is called
   `Strict` because, unlike most of Nix, it forces its inputs eagerly here).
2. **Extract the special attributes** that control derivation structure rather
   than becoming env vars: `name`, `system`, `builder`, `args`, `outputs`,
   `__structuredAttrs`, `__ignoreNulls`, `outputHash`, `outputHashAlgo`,
   `outputHashMode`, `__contentAddressed`, and the `allowedReferences` /
   `disallowedReferences` family (which become env vars but are validated).
3. **Coerce every remaining attribute to a string**, in a *deterministic
   attribute order* (§6), accumulating string contexts (§8) as it goes. Each
   coerced attribute becomes one entry in `environment`. The coercion rules are
   exact: booleans become `"1"`/`""`, integers become decimal, lists become
   space-joined coercions of their elements, paths get copied to the store and
   become their store path (adding to `input_sources`), nested attrsets with an
   `outPath` are coerced via that, etc. Any deviation here changes an env value
   and thus the hash.
4. **Resolve `outputs`.** Default is `["out"]`. A space-joined or list value
   produces multiple outputs. For input-addressed outputs, each output's `path`
   is left as a *placeholder* during context accumulation and filled in after
   the hash-modulo computation (§5.3). For fixed-output and CA derivations,
   `ca_hash` is populated from `outputHash*`.
5. **Partition the accumulated string contexts** into `input_derivations`
   (context elements that name a `.drv` output) and `input_sources` (context
   elements that name a plain store path). This partition is the *only* place
   the derivation's dependency edges come from — there is no separate dependency
   declaration in Nix; the contexts *are* the dependency graph (§8).
6. **Build the `Derivation` struct**, serialize to ATerm (§4), compute the drv
   path (§5.1) and output paths (§5.3), write the `.drv` to the store, and
   return an attrset `{ drvPath = …; outputs = { out = …; … }; }` whose strings
   carry the appropriate output contexts so downstream expressions thread the
   dependency forward.

Steps 3, 5, and the placeholder/hash-modulo dance in 4–5 are where the
subtle bugs live. We reproduce them not by reading the manual (which is
incomplete, as our research confirmed — see §References) but by *differential
testing against `nix-instantiate`* until the bytes match across the full AOS
package set.

### 3.2 `__structuredAttrs` and `__ignoreNulls`

Two special inputs change the env-construction rules and must be handled or the
hash diverges on any package that uses them (nixpkgs' stdenv increasingly does):

* **`__ignoreNulls = true`**: attributes whose value is `null` are *omitted*
  from `environment` entirely, rather than coerced. Get this wrong and you emit
  an extra (or missing) env var.
* **`__structuredAttrs = true`**: instead of coercing each attribute to an env
  var, Nix serializes the non-special attributes into a single JSON blob, sets
  the `__json` environment variable to that blob, and arranges
  `NIX_ATTRS_JSON_FILE` at build time. The JSON encoding has its own ordering
  and escaping rules that must match. This is effectively a second, nested wire
  format inside the env; we treat it as a distinct conformance target in the
  differential harness.

These are flagged here because they are precisely the kind of "rare but
load-bearing" behavior that a from-scratch reimplementation under-tests. The
[roadmap and risks](17-roadmap-and-risks.md) register lists `__structuredAttrs`
as a named long-tail divergence risk.

---

## 4. ATerm serialization: the exact wire format

The `.drv` file is the derivation rendered in a Nix-specific subset of the
**ATerm** format (a term-serialization syntax originating in the ASF+SDF
meta-environment / the ATerm library; Nix uses only its `Cons(...)` /
tuple / list / quoted-string fragment). A derivation serializes to a single
`Derive(...)` term. The field order is fixed and is the following seven-tuple:

```text
Derive(
  [ (outName, outPath, hashAlgo, hash), ... ],   # outputs, sorted by outName
  [ (drvPath, [outName, ...]), ... ],            # inputDrvs, sorted by drvPath
  [ srcPath, ... ],                              # inputSrcs, sorted
  "system",                                      # e.g. "x86_64-linux"
  "builder",                                     # builder path
  [ "arg", ... ],                                # builder args, in order
  [ ("envName", "envValue"), ... ]               # env, sorted by envName
)
```

Concretely, for a trivial input-addressed derivation, the bytes look like:

```text
Derive([("out","/nix/store/abc…-hello","","")],[("/nix/store/def…-bash.drv",["out"])],["/nix/store/ghi…-builder.sh"],"x86_64-linux","/nix/store/jkl…-bash/bin/bash",["-e","/nix/store/ghi…-builder.sh"],[("buildInputs",""),("name","hello"),("out","/nix/store/abc…-hello"),("system","x86_64-linux")])
```

Serialization rules we must reproduce exactly (each one is a past or potential
divergence):

1. **No whitespace.** The serialized form is dense — no spaces, no newlines
   between elements. Any pretty-printing changes the hash.
2. **Element ordering inside the tuple is fixed** (the seven positions above)
   and **list elements are sorted** for outputs (by output name), inputDrvs (by
   drv path), inputSrcs (lexicographically), and env (by key). `arguments` is
   *not* sorted — it preserves the user-given order. Mixing these up is the
   classic byte-divergence bug; we sort using `BTreeMap`/`BTreeSet` keyed on the
   exact same byte ordering C++ Nix uses (plain bytewise on the UTF-8/byte
   representation, *not* locale-aware collation).
3. **String quoting and escaping.** Strings are wrapped in `"`. The escape set
   is exactly: `"` → `\"`, `\` → `\\`, newline → `\n`, carriage return → `\r`,
   tab → `\t`. *No other escaping.* In particular, arbitrary other bytes pass
   through verbatim (this is why env values are `BString`). A reimplementation
   that, say, also escapes `$` or JSON-escapes, or that escapes via Rust's
   `escape_default`, diverges.
4. **Empty output fields.** For input-addressed outputs the `hashAlgo` and
   `hash` positions are empty strings `""`; for fixed-output/CA outputs they
   carry the method-prefixed algo (e.g. `"r:sha256"` for recursive/NAR mode)
   and the digest. The output `path` is empty `""` for floating CA outputs.
5. **The name is not in the ATerm.** Critically — and confirmed against the Nix
   reference manual — *the ATerm does not contain the derivation's `name`.* The
   name lives only in the *filename* of the `.drv` (`<hash>-<name>.drv`) and is
   threaded into the drv-path text-hash separately (§5.1). This is a frequent
   surprise and a source of bugs in naïve implementations that try to round-trip
   name through the term.

We do not hand-roll this. `nix_compat::derivation::Derivation::to_aterm_bytes()`
already implements it, with `from_aterm_bytes()` as the inverse parser and a
unit-test corpus. Our contribution is to *feed it the right struct* — all the
hard problems above (ordering, coercion, context partition) are upstream of the
serializer, in `derivationStrict`. We additionally run the serializer's *output*
through the differential harness against real `.drv` files, because depending on
`nix-compat` for the format does not absolve us of verifying that *our struct
population* was correct.

---

## 5. Store-path computation: the two hashing regimes

There are two distinct hashing computations, and both use **SHA-256** because
that is the on-disk Nix store format. This is non-negotiable: store paths are
SHA-256-derived no matter what faster hash we use *internally* (we use xxh3 and
blake3 for our own caches — see §9 and [incremental evaluation cache](12-incremental-evaluation-cache.md) —
but those never touch a Nix-observed path).

### 5.1 The `.drv` store path (text hashing)

A `.drv` file is itself a store object, placed by the **`text`** store-path
method. Its path is computed as `build_text_path`:

```text
drvPath = makeStorePath(
    type        = "text:" + sorted(references) joined,   # the refs the drv names
    hash        = sha256( ATerm_bytes_of_derivation ),
    name        = derivationName + ".drv"
)
```

where `references` are `input_sources ∪ keys(input_derivations)` (the store
paths the derivation textually mentions), and `makeStorePath` is Nix's standard
"fingerprint → compressed hash → base-32 → `/nix/store/<32 chars>-<name>`"
procedure. The fingerprint string is
`"<type>:sha256:<base16 hash>:<storeDir>:<name>"`, hashed with SHA-256, then
the 32-byte digest is **folded down to 20 bytes** ("compressHash" — XOR-folding,
*not* truncation: byte `i` of the output is the XOR of every input byte at index
`i mod 20`) and rendered in Nix's custom base-32 alphabet
(`0123456789abcdfghijklmnpqrsvwxyz`, omitting `e o t u`). `nix-compat`
implements all of this; we call it.

The note from §4 returns here: the `name` ( `+ ".drv"`) participates in the
*path* hash even though it is absent from the *ATerm content* hash. Two facts,
one hash each, easy to cross-wire.

### 5.2 Hash-derivation-modulo: the indirection that makes fixed-output work

Before output paths can be computed for input-addressed derivations, Nix
computes a value called the **derivation hash modulo** (`hashDerivationModulo`).
This is the subtle heart of input-addressing and the part most likely to
diverge if reimplemented from scratch, so it gets its own treatment.

The naïve idea — "an output path is the hash of the drv" — is *almost* right but
has a chicken-and-egg problem and a fixed-output special case:

* **Fixed-output derivations** (those with `outputHash`, e.g. every `fetchurl`)
  must have a *stable* output path determined only by their declared content
  hash, *not* by their inputs. Otherwise changing the URL mirror or the curl
  version would change the output path of a tarball whose content is identical —
  defeating the entire point. So a fixed-output derivation's contribution to
  downstream hashes is replaced by `sha256("fixed:out:" + algoMode + ":" +
  digest + ":" + outPath)` — a fingerprint of *just* its declared output hash
  and its (already content-derived) output path, not its inputs.

* **Input-addressed derivations** contribute the SHA-256 of their ATerm — but
  with every *input derivation reference inside that ATerm textually replaced by
  that input's own hash-modulo*, computed recursively. This "modulo" rewriting
  is what lets the recursion bottom out at fixed-output leaves and makes the
  whole closure's identity depend on *content at the fixed-output frontier* and
  *structure above it*.

`nix_compat` exposes this as `hash_derivation_modulo`, documented (per our
research) as returning "the sha256 digest of the derivation ATerm
representation" with the input-drv substitution applied. We rely on it, but we
single it out as the #1 differential-testing focus, because a subtle error here
produces a *systematic* divergence on every input-addressed path — i.e. the
whole store — rather than a localized one.

```text
hashDerivationModulo(drv):
    if drv is fixed-output (single out with ca_hash, classic FOD shape):
        return sha256( "fixed:out:" + algoMode + ":" + digest + ":" + outPath )
    else:
        drv' = drv with each inputDrv key K replaced by
               hex(hashDerivationModulo(drv_of(K)))   # recursive, memoized
        return sha256( ATerm_bytes(drv') )
```

Memoization here is not optional for performance: a from-source distro's
derivation closure re-references the same toolchain drvs thousands of times, so
`hashDerivationModulo` is computed once per drv and cached — this is a natural
client of our [incremental evaluation cache](12-incremental-evaluation-cache.md)
keyed by drv path.

### 5.3 Input-addressed output paths

With the modulo value `H = hashDerivationModulo(drv)` in hand, each output's
store path is:

```text
outputPath(outName) = makeStorePath(
    type = "output:" + outName,
    hash = H,                      # the hash-modulo, NOT the raw drv ATerm hash
    name = derivationName + (outName == "out" ? "" : "-" + outName)
)
```

So `out` of a package named `hello` becomes `…-hello`, while its `dev` output
becomes `…-hello-dev`. These paths are then back-patched into the `outputs`
field of the derivation (replacing the placeholders from §3.1 step 4) *and* into
the corresponding env vars (Nix sets `$out`, `$dev`, … in the build env to these
paths), which means the ATerm that gets *written* contains the resolved paths —
a second self-referential subtlety (`hashDerivationModulo` is computed over the
ATerm with placeholders for the self-outputs in the env, then the resolved paths
are substituted in for serialization). We reproduce C++ Nix's exact placeholder
scheme (the `/0c6rn30q4frg…`-style "unknown output" placeholders) rather than
inventing our own, because the placeholder bytes are themselves hashed.

### 5.4 Content-addressed (CA) derivation outputs

CA derivations (NixOS RFC-0062) make the output path depend on the *built
content* rather than the inputs. At *evaluation* time we cannot know that
content, so the output `path` is left empty and the output is "floating,"
carrying only its `ca_hash` method (`r:sha256` for NAR/recursive,
`sha256` for flat). The actual path is resolved at *realisation* time (which
Nix, not aos-nix, performs). Fixed-output derivations are the degenerate, fully
predetermined case of CA outputs and *are* resolvable at eval time (their
content hash is declared up front), which is why `fetchurl`'s output path is
known before anything is fetched.

For the AOS package set as it stands today (input-addressed, from-source), CA
derivations are a minority. But they are the bridge to early cutoff at the
*build* layer and the direct tie-in to RFC-0005 (§10), so the design carries
them as a first-class case even where the current package set rarely exercises
them.

---

## 6. Deterministic ordering: the single highest-risk surface

Because every ordered-but-sorted list in the ATerm is part of the hash,
*ordering bugs are the dominant divergence class*, and they are insidious
because they only manifest on derivations with ≥2 entries in some sorted field.
We enumerate the ordering contracts explicitly so they can be tested
exhaustively:

| Field | Order | Sort key | Notes |
|-------|-------|----------|-------|
| `outputs` | sorted | output name, bytewise | empty algo/hash for input-addressed |
| `input_derivations` | sorted | drv store path, bytewise | inner output-name set also sorted |
| `input_sources` | sorted | store path, bytewise | |
| `environment` | sorted | env var name, bytewise | this is the big one |
| `arguments` | **insertion** | n/a — preserves user order | NOT sorted |
| attr coercion order in §3.1 step 3 | by attr name | bytewise | drives env order AND context accumulation order |

Two ordering facts deserve emphasis:

1. **Bytewise, not locale-aware.** Nix sorts by raw byte value (it is comparing
   `std::string`s / `&[u8]`), not by any Unicode collation or locale. A Rust
   `BTreeMap<String, _>` sorts by `str` `Ord`, which is bytewise on UTF-8. The
   current tree-walk implementation UTF-8-checks environment keys before they
   enter `nix_compat::derivation::Derivation`, stores environment values as
   `BString`, and relies on the ordered derivation containers plus property
   coverage to catch any future non-ASCII-key mismatch against `nix-compat`'s
   ordering.

2. **Attribute iteration order in the language also matters here.** The order in
   which `derivationStrict` *coerces* attributes (§3.1 step 3) affects the order
   in which string contexts are accumulated and — for any coercion that has a
   side effect like copying a path to the store — the order of those effects.
   Nix attrsets have a *defined* iteration order (sorted by interned symbol's
   *string*, which our [attribute sets](09-attribute-sets-hidden-classes-and-inline-caches.md)
   document commits to reproducing). The final env is re-sorted bytewise anyway,
   so env *order* is robust to this, but anything order-sensitive in coercion is
   not, and we keep the same coercion traversal order as C++ Nix.

The mitigation is structural: we do not *trust* our ordering; we *diff* it.
Every ordered field is exercised by the differential harness on real
multi-output, multi-input, many-env-var derivations from the AOS set
(`gcc`, `glibc`, `systemd`, and the structured-attrs-heavy stdenv are the
torture tests). See [differential testing and benchmarking](15-differential-testing-and-benchmarking.md).

---

## 7. The `nix-compat` dependency: buy the format, build the evaluator

A deliberate and important scoping decision: **we do not reimplement the store
format. We reuse `nix-compat`.**

`nix-compat` is the Rust crate (from TVL's Tvix project, now carried in the
**Snix** fork that the ecosystem was renamed to; `devenv` adopted the Tvix
evaluator in October 2024) that provides compatibility primitives for C++ Nix:
store-path construction, the base-32
alphabet and `compressHash`, NAR serialization, narinfo, the `Derivation` data
model, ATerm read/write (`to_aterm_bytes` / `from_aterm_bytes`), `.drv` path
calculation (`build_text_path`), output-path calculation, and
`hash_derivation_modulo`. Its derivation module is explicitly documented as
containing "the Derivation internal data model, ATerm serialization and output
path calculation … and a Derivation ATerm parser."

The rationale for depending on it rather than rolling our own:

* **The format is the contract, and someone already paid the byte-debugging
  tax.** `nix-compat` carries a unit-test corpus and is exercised by Snix
  against nixpkgs. Reimplementing ATerm + `compressHash` + base-32 +
  hash-modulo from scratch would be re-walking a minefield that another project
  has already cleared, for zero differentiation — the format is not where
  aos-nix is trying to be novel. Our novelty is *evaluation speed* (the
  incremental cache, tiering, GC), upstream of the serializer.
* **It sharpens the layering.** With `nix-compat` owning the format, the
  compatibility surface of *our* code collapses to "did `derivationStrict`
  populate the `Derivation` struct correctly and in the right order?" — a much
  smaller, more testable target than "is every byte of ATerm right?"
* **It hermetically fits AOS.** `nix-compat` is pure Rust with a small
  dependency set; we package it as an AOS crate built from a **pinned git rev**
  (see [build principles](../../../CLAUDE.md)) rather than tracking a moving
  target.

The risk, recorded honestly in the [roadmap and risks](17-roadmap-and-risks.md)
register: **`nix-compat` / Snix APIs are pre-1.0 and unstable.** The Snix CLI is
explicitly disclaimed as unstable, and the crate's surface has churned. Our
mitigations:

1. **Pin a git rev.** We do not float on `main`. Upgrades are deliberate and
   re-validated through the differential harness.
2. **Wrap it behind our own thin adapter** (`aos_nix_compat::drv`) so an upstream
   rename does not ripple through the evaluator.
3. **Expect to contribute upstream.** Our acceptance bar — *byte-identical on
   the AOS set* — may be stricter than Snix's, which targets nixpkgs-correctness
   and does *not* guarantee `.drv` parity. If we find a `nix-compat` divergence
   from C++ Nix, we fix it and upstream rather than fork. A stated expectation,
   not a hope.

It is worth stating the boundary of trust precisely: depending on `nix-compat`
removes the *format* from our risk surface but **not** the *correctness of our
inputs to it*. The differential harness validates our end-to-end `.drv` bytes,
so a latent `nix-compat` bug surfaces as a harness failure on a real package —
at which point we either fix our struct population or fix/patch `nix-compat`. We
never ship a green evaluator on the back of an unverified format assumption.

---

## 8. String contexts: the dependency graph hiding inside strings

String contexts are the mechanism by which Nix tracks "this string mentions a
store path, so anything built from it depends on that path." They are
**invisible in idiomatic Nix code** — you never write one — but they are the
*sole* source of a derivation's dependency edges (§3.1 step 5). Getting them
wrong does not produce a malformed `.drv`; it produces a *plausible* `.drv` with
the *wrong dependencies*, which is the worst kind of bug because it still hashes
to a valid (but wrong, and possibly under-specified) path.

### 8.1 What a context is

Every Nix string value is a pair `(bytes, context)` where the context is a set
of **context elements**. Each element is a *deriving path* of one of a few
kinds (per the Nix reference manual on string contexts):

| Element kind | Written as | Meaning |
|---|---|---|
| constant / opaque path | `/nix/store/…-foo` | "depends on this plain store path" (→ `input_sources`) |
| single output | `!out!/nix/store/…-foo.drv` | "depends on the `out` output of this derivation" (→ `input_derivations`) |
| derivation deep | `=/nix/store/…-foo.drv` | "depends on this drv and its entire build closure" |

When `derivationStrict` walks the coerced attributes (§3.1), it unions the
context of every coerced string. The final union is partitioned: opaque-path
elements become `input_sources`; output elements become entries in
`input_derivations` (grouped by drv path, accumulating the set of referenced
output names); deep elements expand to the drv plus its closure. *That partition
is the dependency graph.* There is no other place dependencies come from.

### 8.2 How contexts propagate through the language

Contexts flow through string operations, and the propagation rules must match
exactly:

* **Concatenation / interpolation** (`a + b`, `"${a}${b}"`) **unions** the
  contexts of the operands.
* **`toString` / coercion** of a derivation attrset uses its `outPath` string,
  carrying that output's context.
* **`builtins.substring`, `replaceStrings`, etc.** preserve the *whole* context
  (Nix does not track *which substring* introduced which path — context is
  string-granular, not byte-granular).
* **`builtins.unsafeDiscardStringContext`** returns the same bytes with an
  *empty* context (used deliberately to break a dependency — e.g. so a string
  can name a path without forcing it to be built).
* **`builtins.unsafeDiscardOutputDependency`** downgrades a `=`/deep element.
* **`builtins.addDrvOutputDependencies`** upgrades a constant element naming a
  `.drv` into a deep element.
* **`builtins.hasContext` / `getContext`** read the context (the latter
  reflecting it into an inspectable attrset), and **`appendContext`** merges a
  reflected context back in. These are how nixpkgs occasionally manipulates
  contexts explicitly.

Each of these is a primop in [primops and runtime ABI](10-primops-and-runtime-abi.md),
and each must implement the exact union/discard semantics above.

### 8.3 Representation: interned, copy-on-write bitsets

The performance design (justified by [value representation](05-value-representation.md)
and [memory management](06-memory-management-and-gc.md)) is:

* **Intern store-path references to dense `u32` ids** in a per-evaluation table
  (the same interning discipline we use for symbols in
  [attribute sets](09-attribute-sets-hidden-classes-and-inline-caches.md)).
* **Represent a context as a bitset / small sorted set of those ids**, with the
  *deriving-path kind* encoded alongside.
* **Copy-on-write**, because the overwhelmingly common context operation is
  *union during concatenation*, and most strings either have an empty context
  (literal text — the common case, share one canonical empty context) or share a
  context with their neighbors. Hash-consing the bitsets (interning structurally
  equal contexts) gives O(1) equality and lets the
  [incremental cache](12-incremental-evaluation-cache.md) hash a context cheaply.

Why this is *sound and cheap here specifically*: Nix values are immutable
([value representation](05-value-representation.md)), so an interned, shared,
copy-on-write context can never be mutated out from under another holder — the
same property that makes hash-consing sound for values makes it sound for
contexts. C++ Nix represents contexts as `std::set<std::string>` of the textual
forms, which re-hashes and re-compares full path strings on every union; our
`u32`-bitset representation is a measured win on the concat-heavy nixpkgs idiom
(`"${stdenv}/bin/${pname}"`-style interpolation appears everywhere), while
producing the *identical* partition into `input_sources` / `input_derivations`.

### 8.4 The compatibility hazard

The hard constraint from [compatibility constraints](02-compatibility-constraints.md)
applies in full force: a string that *should* carry a context but doesn't (a
propagation bug in some obscure primop) yields a `.drv` missing a dependency
edge — it will hash differently *and* may build wrong. Conversely, an *extra*
spurious context element adds a phantom dependency and a phantom env reference.
Both change the bytes. String-context propagation is therefore a top-tier item
in the conformance suite (reusing the C++ Nix language test suite, which has
dedicated context tests, exactly as Tvix/Snix do — §References).

---

## 9. Hashing policy: three hashes, three jobs

A recurring confusion this RFC pre-empts: aos-nix uses *three* hash functions,
and conflating them would be either a correctness bug or a performance own-goal.

| Hash | Where | Why | Visible to Nix? |
|------|-------|-----|-----------------|
| **SHA-256** | drv path, output paths, store-object hashing, fixed-output `outputHash`, NAR/`compressHash` | it is the Nix on-disk format; **non-negotiable** | **YES** — these bytes leave the process |
| **blake3** | the durable, shared, content-addressed *eval* cache ([incremental evaluation cache](12-incremental-evaluation-cache.md)); Attic-shared eval results | cryptographic, collision-safe at fleet scale, fast | NO — internal cache key only |
| **xxh3 (xxHash)** | in-process hot hashing: hash-consing value/context dedup, inline-cache shape ids, transient memo keys | fastest, non-cryptographic, fine for in-process maps where collisions are merely a perf risk | NO — never persisted, never observed |

The rule is a one-liner: **SHA-256 only where Nix can observe the bytes; never
substitute a faster hash there, no matter how tempting.** The from-source distro
would detonate (§1) if we used blake3 for a store path "because it's faster."
Conversely, using SHA-256 for the in-process hash-cons table would needlessly
slow the hot path that SHA-256 is far too heavy for. The boundary is sharp and
enforced by *type*: store-path hashing flows exclusively through `nix-compat`'s
SHA-256 APIs; our own caches use distinct `blake3::Hash` / `u64` (xxh3) types
that *cannot* be passed to a store-path constructor.

---

## 10. RFC-0005 tie-in: the realisation graph and CA derivations

This document defines the *production* of the derivation graph; AOS
[RFC-0005](../0005-ca-trust-map.md) (the `store/` realisation-graph /
content-addressed closure-validation RFC) and RFC-0006 (secure boot,
sign/measure/attest) define what happens to that graph *after* evaluation. The
seam between them is worth making explicit because the design choices here are
partly *for* those downstream RFCs.

* **Deriving paths are the shared vocabulary.** The "single output" and
  "deep" context elements (§8.1) are *deriving paths* in the same sense
  RFC-0005's realisation graph uses. aos-nix emits exactly the deriving paths
  C++ Nix would, so the realisation graph RFC-0005 consumes is identical whether
  the front evaluator is C++ Nix or aos-nix. This is a *non-negotiable* output
  of the byte-parity gate — the realisation graph is downstream of the `.drv`
  bytes.

* **CA derivations enable build-layer early cutoff.** §5.4's floating CA outputs
  are the mechanism by which *two different derivations that build identical
  content* converge on the *same* output path at realisation time. This is the
  build-layer analogue of the *eval-layer* early cutoff in our
  [incremental evaluation cache](12-incremental-evaluation-cache.md): eval-layer
  early cutoff says "the expression's value didn't change, stop recomputing";
  build-layer (CA) early cutoff says "the build's *content* didn't change, stop
  rebuilding downstream." aos-nix does not perform the build-layer cutoff (that
  is realisation, RFC-0005's domain), but it must *emit CA derivations
  correctly* so RFC-0005's machinery can. Hence CA is a first-class case in §3–§5
  even though the present AOS package set is mostly input-addressed.

* **The registry is a validation catalog, never a signer.** Per the RFC-0006
  memory note, the registry validates store paths / realisations but never signs
  derivations. aos-nix's role is upstream of all of that: it *produces* the
  store paths that RFC-0006 later measures/attests. Byte-parity here is what
  makes a measured/attested path produced via aos-nix *indistinguishable* from
  one produced via C++ Nix — the attestation is over the path, and the path is
  identical, by construction. A divergence here would not merely cause a rebuild;
  it would produce a path that fails to match a signed/attested catalog entry.

The thread connecting all three RFCs: **the store path is the universal name.**
RFC-0007 produces it (must be byte-identical), RFC-0005 realises and tracks it,
RFC-0006 measures and attests it. The byte-parity constraint at the top of this
document is therefore not local to evaluation; it is the foundation the entire
AOS trust/realisation stack stands on.

---

## 11. The acceptance gate for this layer

Concretely, "done" for derivation/store compatibility means:

```text
for every package P in the AOS package set:
    drv_native  = aos-nix    -> instantiate(P)        # AOS_NIX_NATIVE=1
    drv_cpp     = nix-instantiate P                   # reference
    assert bytes(drv_native.file)  == bytes(drv_cpp.file)      # ATerm parity
    assert drv_native.path         == drv_cpp.path            # drv-path parity
    assert drv_native.outputs      == drv_cpp.outputs         # output-path parity
    # and recursively for the entire input-derivation closure
```

This runs against the *full transitive closure*, not just leaf packages, because
a single divergence deep in the toolchain (a `glibc` env-ordering bug) poisons
every path above it. The harness ([differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
walks the closure and diffs every `.drv`, reporting the *first* (deepest)
divergence — the root cause, not the thousands of downstream symptoms.

Until this gate is green on the full closure, `AOS_NIX_NATIVE` stays **off by
default** and `NixCli` ([integration with AOS](14-integration-with-aos.md))
remains the path of record. There is no "mostly compatible" intermediate state
that ships: a from-source distro cannot tolerate a 0.1% divergence rate, because
0.1% of the toolchain closure is still a multi-hour rebuild. The gate is binary.

---

## 12. Open questions and research-grade edges

Marked explicitly, per the RFC discipline of not overclaiming:

1. **`__structuredAttrs` JSON byte-parity.** The nested JSON env encoding has
   its own ordering/escaping; we believe `nix-compat` + careful population
   reproduces it, but the AOS stdenv's increasing use of structured attrs makes
   this a *measured* claim pending the harness, not an assumed one. **Open until
   the harness exercises structured-attrs packages.**

2. **`nix-compat` parity vs. our stricter bar.** Snix does not *guarantee* `.drv`
   byte-parity (it defers some edge-correctness until nixpkgs-correct). It is
   possible `nix-compat` diverges from C++ Nix on some construct the AOS set
   exercises. **Mitigation: pinned rev + harness + upstream contribution.**
   Whether any such divergence exists in the current AOS set is an empirical
   question the harness answers.

3. **Placeholder scheme stability.** §5.3's self-referential output placeholders
   are an internal C++ Nix detail; if Nix changes the placeholder derivation
   across versions (it has historically been stable, but it is not a documented
   contract), we must track the *specific* `nix-instantiate` version AOS pins.
   **The differential harness must run against the exact pinned Nix.**

4. **CA-derivation coverage.** **Decision (closed, C-11): CA derivations are
   first-class and in the first gate's scope** — `derivationStrict` implements
   floating and fixed CA outputs in Phase 1, because AOS's store model is
   content-addressed ([RFC-0005](../0005-ca-trust-map.md)). The naturally
   IA-dominated package set under-exercises CA paths, so coverage is *built*, not
   waited for: synthesized CA fixtures plus the RFC-0005 realisation graph
   exercise the CA path in the harness from the start. The residual *empirical*
   risk is that CA's ATerm encoding is the experimental, "not yet stable" part of
   the format, so we pin the exact Nix version (C-9) and track its CA encoding
   deliberately. The design is settled; the encoding is verified by diff, like
   everything else here.

5. **Context-granularity edge cases.** A handful of context primops
   (`addDrvOutputDependencies`, `unsafeDiscardOutputDependency`,
   `appendContext`) are rare in nixpkgs and rarer in the AOS set; their exact
   semantics are reproduced from the C++ source and the language test suite, but
   real-world coverage is thin. **Flagged for the conformance suite.**

None of these threaten the *design*; they are all "verify by differential
testing against the pinned reference," which is the same discipline as
everything else in this layer. The design's defining choice — *do not trust,
diff* — is what converts these from risks into test cases.

---

## Implementation checklist

Per-feature tracker for derivation and store compatibility; master roll-up:
[implementation checklist (all phases)](22-implementation-checklist-all-phases.md).
Per the unlimited-budget mandate, every item here is in scope — including
research-grade ones — built in dependency order and gated by the differential
harness, never cut for scope.

### `nix-compat` dependency and the format boundary (foundation)

- [x] Current `nix-compat` pin and format-substrate use: the workspace dependency pins `nix-compat` to git rev `f9a731021455c402430af1aa1ab749fd2f66293d` with default features disabled; `ratchet-oracle` consumes it for derivation/store-path/nixhash handling, and `aos-nix-harness` consumes it for structural `.drv` parsing. The leaf `aos-nix-compat` crate owns the current `.drv` ATerm edge parser and safe `.drv` materialization helper so those format-adjacent surfaces are no longer embedded in `aos-core` or `ratchet-oracle`. Adjacent derivation/store-path checklist rows cover the current format-use gates ([§7](#7-the-nix-compat-dependency-buy-the-format-build-the-evaluator)) — P1/P1b, `S-13`/`C-5`; gate: pinned Cargo dependency plus derivation/store compatibility tests.
- [ ] Vendor/adapter hardening remains: vendor only patched `nix-compat` modules when patches are needed, continue extracting direct `nix_compat` use behind thin `aos_nix_compat` adapter boundaries where a pure API exists, and require the differential `.drv` harness on every `nix-compat` bump ([§7](#7-the-nix-compat-dependency-buy-the-format-build-the-evaluator)) — P1/P1b, `S-13`/`C-5`; gate: adapter-boundary audit plus differential `.drv` harness on each bump.
- [x] `Derivation` seven-field struct populated correctly (`outputs`, `input_sources`, `input_derivations`, `system`, `builder`, `arguments`, `environment`) through `nix_compat::derivation::Derivation`; `derivationStrict` fills the field set, validates required `system`/`builder` and derivation-name legality (including illegal bytes such as `~`), defaults `out`, inserts output env entries, and records known derivations for downstream input hashing ([§3](#3-the-store-derivation-what-derivationstrict-produces)) — P1, `S-13`; gate: differential `.drv` harness.
- [x] `BString` env values (lossless arbitrary-byte round-trip), `BTreeMap`/`BTreeSet` deterministic ordering for outputs, input derivations, input sources, and environment. Non-UTF-8 environment values survive into ATerm bytes while structural fields remain UTF-8-checked before insertion ([§3](#3-the-store-derivation-what-derivationstrict-produces)) — P1; gate: property test vs `nix-compat` ordering.

### `derivationStrict` algorithm

- [x] Six-step algorithm: force-to-WHNF, extract special attrs, deterministic-order string coercion with context accumulation, resolve `outputs`, partition contexts into inputs, build+serialize+hash+write. The tree-walk implementation clones attr entries in lexicographic order for `derivationStrict`, accumulates `StringContext`, resolves fixed/floating/impure output modes, computes input hashes for known derivations, records ATerm bytes, and exposes the resulting `.drvPath`/outputs as context-bearing strings ([§3.1](#31-the-derivationstrict-algorithm-step-by-step)) — P1, `S-13`; gate: differential `.drv` harness.
- [x] Exact coercion rules (bool → `"1"`/`""`, int decimal, list space-join, path → store copy + `input_sources`, attrset-with-`outPath`) are implemented through the shared string-coercion path used by `derivationStrict`, with tests covering argument coercion, path/store context flow, attrset derivation coercion, and structured-attrs exceptions ([§3.1](#31-the-derivationstrict-algorithm-step-by-step)) — P1; gate: conformance 20-21.
- [x] `__ignoreNulls` (omit null attrs) and `__structuredAttrs` (`__json` blob, nested JSON ordering/escaping) ([§3.2](#32-__structuredattrs-and-__ignorenulls)) — P1, `M-20`; gate: harness on structured-attrs packages (torture: stdenv).

### ATerm serialization

- [x] `Derive(...)` seven-tuple serialization: no whitespace, fixed field positions, sorted outputs/input derivations/input sources/environment from ordered containers, and insertion-order `arguments` from the evaluated `args` list. Static, floating-CA, impure, deferred-placeholder, and input-hash-substituted forms share the same explicit ATerm writers ([§4](#4-aterm-serialization-the-exact-wire-format)) — P1, `S-13`; gate: differential `.drv` harness (byte parity).
- [x] Exact string escaping (`"`, `\`, `\n`, `\r`, `\t` only; all other bytes verbatim); empty output fields for IA/deferred outputs; derivation `name` participates in path naming but is not an ATerm field except as a normal environment entry when C++ Nix would emit it ([§4](#4-aterm-serialization-the-exact-wire-format)) — P1; gate: harness.

### Store-path computation (both addressing regimes)

- [x] `.drv` text path via `build_text_path`: ATerm bytes are SHA-256 hashed, references are `input_sources ∪ keys(input_derivations)`, the fingerprint is folded through `nix_compat::store_path::compress_hash`, and the store path name is `<derivation-name>.drv` while the derivation `name` itself is absent from the ATerm tuple ([§5.1](#51-the-drv-store-path-text-hashing)) — P1, `S-13`; gate: drv-path parity.
- [x] **Input-addressed path:** `hash_derivation_modulo_with_inputs` bottoms fixed-output derivations at their fixed digest, substitutes known input-derivation hashes, derives `output:<name>` paths, and records deferred placeholder forms for downstream users of unresolved CA/impure outputs ([§5.2](#52-hash-derivation-modulo-the-indirection-that-makes-fixed-output-work)–[§5.3](#53-input-addressed-output-paths)) — P1, `S-13`/`C-6`/`R-11`; gate: differential `.drv` harness (#1 focus).
- [x] **Content-addressed path:** floating CA outputs (empty ATerm output path plus `r:sha256`/`sha256` method), fixed-output derivations, and impure deferred-output derivations are first-class in the tree-walk builder; downstream consumers use placeholder/path hashing until realization supplies content ([§5.4](#54-content-addressed-ca-derivation-outputs)) — P1, `C-11`/`C-6`; gate: harness with synthesized CA fixtures + RFC-0005 graph.

### Deterministic ordering (highest-risk surface)

- [x] Every sorted ATerm field is emitted from deterministic ordered containers: `outputs`, `input_derivations` (+ inner output-name set), `input_sources`, and `environment`; `arguments` remain insertion-order from the evaluated `args` list. The package-wide full-closure stress gate remains the downstream proof for large real derivations ([§6](#6-deterministic-ordering-the-single-highest-risk-surface)) — P1, `S-2`; gate: differential `.drv` harness on multi-output/multi-input/many-env-var packages (gcc/glibc/systemd).
- [x] Attr coercion traversal order matched to the tree-walk observable order: `derivationStrict` iterates attrs lexicographically for environment/context accumulation, while structured-attrs JSON and reflected context attrs use their documented source/lexicographic orders where C++ Nix observes them ([§6](#6-deterministic-ordering-the-single-highest-risk-surface), [09 §7](09-attribute-sets-hidden-classes-and-inline-caches.md)) — P1; gate: harness.

### String contexts (the dependency graph inside strings)

- [x] Context-element kinds (constant/opaque, single-output `!out!`, deep `=`) and the partition into `input_sources` / `input_derivations` are implemented by `ContextKind::{OpaquePath, SingleOutput, DeepDerivation}` plus `add_derivation_context_inputs`; single-output contexts become named input-derivation edges, deep contexts expand known outputs and add the derivation to input sources, and opaque paths become input sources ([§8.1](#81-what-a-context-is)) — P1, `S-13`; gate: conformance 20-21.
- [x] Propagation rules: union on concat/interp; `toString` carries `outPath` context; whole-context preservation through `substring`/`replaceStrings`; `unsafeDiscardStringContext`/`unsafeDiscardOutputDependency`/`addDrvOutputDependencies`/`hasContext`/`getContext`/`appendContext`. These are covered by focused context tests plus configured C++-Nix oracle helpers where available ([§8.2](#82-how-contexts-propagate-through-the-language)) — P1, `R-12`; gate: differential harness + C++ Nix language test suite (rare primops research-grade).
- [x] Current P1 string-context representation baseline: `StringContext` is an immutable canonical sorted/deduplicated `Vec<ContextElement>`; each element carries raw path bytes, `ContextKind::{OpaquePath, SingleOutput, DeepDerivation}`, and an optional output name, preserving distinct deriving-path kinds/output names for the same path. `NixString` equality/hash and evaluator string consing include the full context, so identical bytes with different contexts remain distinct. This is the correctness baseline, not the future compact interned/COW representation ([§8.3](#83-representation-interned-copy-on-write-bitsets)) — P1, `S-7`/`M-13`; gate: context representation/hash/heap consing tests.
- [ ] Compact string-context representation remains: store-path refs interned to `u32`, context as a COW hash-consed bitset/sorted-set with deriving-path kind and output identity, preserving the current canonical element semantics ([§8.3](#83-representation-interned-copy-on-write-bitsets)) — P1, `S-7`/`M-13`; gate: harness (hazard #2).

### Hashing policy

- [x] Current three-hash routing substrate: Nix-observable `.drv`/store/fetcher/hash-builtin paths use SHA-256 (`sha2` plus `nix-compat` store/nixhash APIs where applicable), durable parse/import cache keys use BLAKE3, and evaluator-local string/path cons-table structural hashes use xxh3 with equality confirmation and no Nix-observable role ([§9](#9-hashing-policy-three-hashes-three-jobs)) — P1/P2, `S-15`; gate: derivation/hash builtin, parse-cache key, and heap/string structural-hash tests.
- [x] Current typed hash-domain boundary for the implemented substrate: `cache::hashing::HotXxh3Hash` is threaded through `NixString::structural_hash_xxh3`, heap cons buckets, and heap-record structural hashes for evaluator-local xxh3 probes, while `cache::hashing::DurableBlake3Hash` backs `ParseCacheKey` and `ParseFileKey` for durable parse/file cache addresses. This separates the current internal xxh3 and BLAKE3 domains from each other at the Rust type level without changing any Nix-observed SHA/store/hash-builtin paths ([§9](#9-hashing-policy-three-hashes-three-jobs)) — P1/P2 precursor, `S-15`; gate: `cache::hashing` tests, `cache::parse` tests, heap consing tests, and Nix-observed hash/fetch/derivation tests.
- [x] Current `.drv` surface leak canary for internal cache hashes: `internal_cache_hash_canaries_do_not_reach_drv_surfaces` evaluates a static derivation through configured parse/persist cache roots while importing a real temporary file, computes the actual current parse-cache BLAKE3 keys for the root and imported sources, the `ParseFileKey` content hash for the imported file, and the evaluator-local xxh3 structural hash for the derivation name string, and asserts the recorded `.drv` ATerm bytes and `.drv` store path do not contain those internal digest renderings, Nix-base32 encodings, or raw digest bytes. It also asserts the configured import parse-cache miss/write and persistent file-artifact mapping occurred. This is a selected current-substrate regression canary, not the full type-enforced leak-invariant API or harness ([§9](#9-hashing-policy-three-hashes-three-jobs)) — P1/P2 precursor, `S-15`; gate: focused derivation canary test.
- [x] Current cache-on/cache-off `.drv` surface parity canary: `configured_import_cache_preserves_drv_surfaces` evaluates the same imported-file derivation with import caching disabled, with configured parse/persist roots on a miss/write path, and with a later persistent-hit path, then requires identical `.drv` paths and ATerm bytes across all three runs. This is selected current-substrate coverage that cache metadata does not perturb that derivation surface, not the full cached/uncached closure parity gate ([§9](#9-hashing-policy-three-hashes-three-jobs)) — P1/P2 precursor, `S-15`; gate: focused derivation cache-surface parity test.
- [ ] Full type-enforced leak-invariant remains: introduce APIs/tests that prevent BLAKE3/xxh3 digests from reaching Nix-observed store-path/hash constructors across all future value/demand-cache paths, tighten store-path hashing behind the `nix-compat` adapter boundary where applicable, and run a leak-invariant harness across `.drv`/store/fetch/hash builtin surfaces ([§9](#9-hashing-policy-three-hashes-three-jobs)) — P1/P2, `S-15`; gate: leak-invariant harness.

### Acceptance gate and RFC-0005/0006 tie-in

- [x] Current differential `.drv` harness substrate for this layer: `aos_nix_harness::diff::diff_closure` compares C++-Nix-oracle and candidate root `.drv` paths in path/byte/structural modes; byte/structural modes walk input derivations when closure bytes are available through `instantiate_closure` or bundle-backed reruns, compare ATerm bytes per node, and structural mode localizes parsed-field differences through `nix-compat`. `DrvDiffReport` classifies root-vs-contaminated divergence nodes, and `aos nix-diff` exposes direct node reruns ([§11](#11-the-acceptance-gate-for-this-layer), [15 §2](15-differential-testing-and-benchmarking.md#2-the-differential-drv-diff-harness-the-acceptance-gate)) — P1, `S-2`/`C-18`; gate: `aos-nix-harness` diff/CLI tests plus native-eval integration when available.
- [ ] Full green acceptance result remains: run the binary gate over the auto-derived full AOS package/system/toolchain/conformance corpus and require zero divergences for `.drv` roots, ATerm bytes, drv paths, and serialized output paths before any default-on decision; keep default-off until that full transitive-closure result is green ([§11](#11-the-acceptance-gate-for-this-layer)) — P1, `S-2`/`C-18`; gate: full differential `.drv` harness run.
- [x] Current deriving-path/CA emission substrate ties together the rows above: string contexts carry the Nix deriving-path kinds used to partition derivation inputs, and the tree-walk derivation builder emits the fixed-output, floating-CA, impure, and deferred-placeholder forms RFC-0005 will consume ([§10](#10-rfc-0005-tie-in-the-realisation-graph-and-ca-derivations), [§5.4](#54-content-addressed-ca-derivation-outputs), [§8.1](#81-what-a-context-is)) — P1, `C-11`; gate: CA/fixed-output/deferred-output derivation tests plus context partition tests.
- [ ] Full RFC-0005 realisation-graph parity remains: prove deriving-path parity makes RFC-0005's realisation graph identical regardless of front evaluator, and prove correct CA emission enables build-layer early cutoff with the full harness + RFC-0005 graph gate ([§10](#10-rfc-0005-tie-in-the-realisation-graph-and-ca-derivations)) — P1, `C-11`; gate: full differential harness + RFC-0005 realisation graph.

---

## References

Verified against primary sources during authoring:

- Nix Reference Manual, *Store Derivation and Deriving Path* (the `Derive(...)`
  ATerm overview; confirms the name is **not** in the ATerm; text/CA methods):
  <https://nix.dev/manual/nix/2.32/store/derivation/> and the linked ATerm
  protocol page <https://nix.dev/manual/nix/2.32/protocols/derivation-aterm>
- Nix Reference Manual, *Content-addressing derivation outputs* (input- vs.
  content-addressed output paths; fixed-output special case):
  <https://releases.nixos.org/nix/nix-2.31.0/manual/store/derivation/outputs/content-address.html>
- Nix Reference Manual, *String context* (deriving-path element kinds —
  constant/output/deep; `hasContext`, `getContext`, `unsafeDiscardStringContext`,
  `addDrvOutputDependencies`): <https://nix.dev/manual/nix/2.32/language/string-context>
- Nix Reference Manual, *Advanced Attributes* (`__structuredAttrs`,
  `__ignoreNulls`, `outputHash`/`outputHashAlgo`/`outputHashMode`, fixed-output
  path depends only on `outputHash*` + `name`):
  <https://nix.dev/manual/nix/2.18/language/advanced-attributes.html>
- NixOS RFC-0062, *Content-addressed paths* (CA-derivation model):
  <https://github.com/NixOS/rfcs/blob/master/rfcs/0062-content-addressed-paths.md>
- Tweag, *Derivation outputs and output paths in a content-addressed world*
  (input- vs. content-addressed output-path computation explained):
  <https://www.tweag.io/blog/2021-02-17-derivation-outputs-and-output-paths/>
- `nix_compat::derivation::Derivation` rustdoc (the seven fields; `to_aterm_bytes`,
  `serialize`, `from_aterm_bytes`; `calculate_derivation_path` via
  `build_text_path`; `calculate_output_paths` via `hash_derivation_modulo`;
  **sha256** digest of the ATerm): <https://docs.tvix.dev/rust/nix_compat/derivation/struct.Derivation.html>
  and `Output`: <https://docs.tvix.dev/rust/nix_compat/derivation/struct.Output.html>
- Snix project component overview (the post-Tvix-fork home of `nix-compat`):
  <https://snix.dev/docs/components/overview/>
- devenv, *Switching its Nix implementation to Tvix* (Oct 2024 adoption of the
  Tvix/Snix evaluator; corroborates prior-art status):
  <https://devenv.sh/blog/2024/10/22/devenv-is-switching-its-nix-implementation-to-tvix/>
- TVL blog, *Tvix Status — February '24* (nix-compat's role: ATerm subset,
  fingerprint-of-hashes-then-rehash; context for the hash-modulo design):
  <https://tvl.fyi/blog/tvix-update-february-24>
- NixOS/nix issue #9189, *Explanation of how output hashes are derived*
  (community walkthrough of `hashDerivationModulo`):
  <https://github.com/NixOS/nix/issues/9189>
- NixOS/nix issue #7569, *Discrepancy in `outputs` handling between derivation /
  derivationStrict* (the `derivation` vs `derivationStrict` coercion subtlety):
  <https://github.com/NixOS/nix/issues/7569>
