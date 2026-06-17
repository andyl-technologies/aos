# RFC-0007 - Builtins conformance catalog

> Part of the RFC-0007 documentation set for **aos-nix**, a Rust Nix evaluator
> that must produce `.drv` files and store paths **byte-for-byte identical** to
> the single pinned open-source C++ Nix version AOS builds against. This document
> is the *tickable enumeration* of every `builtins.*` primop the evaluator must
> implement for parity: grouped by area, each with a signature, a one-line
> semantics/parity note, and the edge cases that bite.
>
> It is the companion to [the Nix language conformance catalog](20-nix-language-conformance.md),
> which covers pure syntax and the evaluation core (laziness, scoping, operators,
> coercion). **This document does not re-cover language syntax** — only the
> builtin *function* surface reached through the `builtins` set (and the small
> set of names mirrored into global scope). The runtime mechanics of how a
> builtin is dispatched, forced, and linked live in
> [primops and the runtime ABI](10-primops-and-runtime-abi.md); the derivation
> output boundary lives in [derivation and store compatibility](11-derivation-and-store-compatibility.md);
> the impure-effect caching contract lives in
> [the incremental evaluation cache](12-incremental-evaluation-cache.md).
>
> Cross-references use relative filenames only.

---

## 0. How to read this catalog

Each builtin is a checklist item:

```text
- [ ] `name` (arg0 arg1 …) — one-line semantics + the parity hazard.
      - edge case
      - edge case
```

The conformance bar is *not* "behaves reasonably." It is: for every input the
AOS package set (and the C++ Nix language test suite) exercises, aos-nix returns
a value structurally identical to C++ Nix — including string-context bits, attr
ordering, number formatting, error catchability, and forcing order — such that
the resulting `.drv` bytes match (see
[derivation and store compatibility](11-derivation-and-store-compatibility.md) §11).
Every item below is gated by the differential harness
([differential testing and benchmarking](15-differential-testing-and-benchmarking.md)),
never by an isolated unit test.

**Scope of the authoritative set.** The *truth* of which builtins exist is
`builtins.attrNames builtins` of the **pinned** reference `nix`, diffed by the
harness against aos-nix's own `builtins` set (membership *and* order — see
[primops and the runtime ABI](10-primops-and-runtime-abi.md) §4.4). The catalog
below is transcribed from the Nix reference manual *Built-ins* page (see
References) and pruned of anything that is a `lib` function rather than a real
primop. Where a builtin is recent, the version-introduced is noted so the
pinned-version decision (§16) is auditable.

**A note on prior errata.** An earlier draft of doc 10 listed a primop that does
not exist and two `lib` functions as if they were builtins. This catalog is
written from the manual and source, not from memory. The known traps are called
out inline: `toLower`/`toUpper`/`toTOML`/`concatStrings`/`stringToCharacters`
are **`lib`, not `builtins`** (§17), and there is **no** `builtins.toTOML`
(only `fromTOML`).

---

## 1. Type predicates and introspection

All predicates force their single argument to WHNF and return a `bool`. They
never error on a "wrong" type — they answer the question. `typeOf` and
`functionArgs` are the introspection escape hatches.

- [x] `isAttrs` (e) — true iff `e` forces to an attribute set.
- [x] `isList` (e) — true iff `e` forces to a list.
- [x] `isFunction` (e) — true iff `e` forces to a lambda, a primop, or a
      partially-applied primop (`PrimopApp`).
      - A partially-applied builtin (`builtins.map`) is a function value and
        must answer `true` (see [primops and the runtime ABI](10-primops-and-runtime-abi.md) §2.2).
- [x] `isString` (e) — true iff `e` forces to a string. Context-carrying strings
      still answer `true`; the context is invisible to the predicate.
- [x] `isInt` (e) — true iff `e` forces to an integer (`i64`). `1.0` is **not**
      an int.
- [x] `isFloat` (e) — true iff `e` forces to a float (`f64`). `1` is **not** a
      float.
- [x] `isBool` (e) — true iff `e` forces to a boolean.
- [x] `isNull` (e) — true iff `e` forces to `null`. (Deprecated in idiom in
      favor of `e == null`, but still a live primop; must exist.)
- [x] `isPath` (e) — true iff `e` forces to a path value (distinct from a
      string; see [language conformance](20-nix-language-conformance.md) on the
      path type).
- [x] `typeOf` (e) — returns the type name string. Parity-critical: the exact
      spelling of each tag must match C++ Nix.
      - Returns one of exactly: `"int"`, `"float"`, `"bool"`, `"string"`,
        `"path"`, `"null"`, `"set"`, `"list"`, `"lambda"`. Note the type of an
        attrset is `"set"` (not `"attrs"`) and a function is `"lambda"`.
- [x] `functionArgs` (f) — returns an attrset mapping each formal of a
      `{ a, b ? …, … }`-pattern lambda to a bool (`true` iff it has a default).
      - On a non-pattern lambda (`x: …`) returns `{}`.
      - On a primop / partially-applied primop the behavior follows C++ Nix
        (it reflects the primop's declared formals, generally `{}` for the
        positional builtins); harness-pin this rather than guessing.
      - Result attr order is the sorted formal names (attrset ordering rule, §6).

---

## 2. Arithmetic

Nix has two numeric types: `i64` integers and `f64` floats. The arithmetic
primops implement C++ Nix's *promotion* rule: if either operand is a float the
result is a float; otherwise integer arithmetic in `i64`. Forcing order is left
operand then right operand, and it is observable (see
[primops and the runtime ABI](10-primops-and-runtime-abi.md) §2.3).

- [x] `add` (e1 e2) — `e1 + e2`. Int+int → int; any float → float. Also the
      desugaring target of the `+` operator on numbers (string/path `+` is in
      [language conformance](20-nix-language-conformance.md)).
      - **i64 overflow throws, does not wrap**, on Nix ≥ 2.25 (NixOS/nix#11188):
        an `add`/`sub`/`mul` that would overflow signed 64-bit raises a catchable
        evaluation error. Older Nix wrapped. Match the pinned version's behavior
        exactly (see [language conformance](20-nix-language-conformance.md) §7.1).
- [x] `sub` (e1 e2) — `e1 - e2`. Same promotion rule.
- [x] `mul` (e1 e2) — `e1 * e2`. Same promotion rule.
- [x] `div` (e1 e2) — `e1 / e2`. **Division by zero throws** (a catchable error).
      - Integer division **truncates toward zero** (C/C++ semantics), *not*
        floor division: `div 7 (-2) == -3`, not `-4`. This is a classic
        divergence point versus floor-dividing languages.
      - Mixed int/float → float division.
- [x] `bitAnd` (e1 e2) — bitwise AND of two integers.
- [x] `bitOr` (e1 e2) — bitwise OR of two integers.
- [x] `bitXor` (e1 e2) — bitwise XOR of two integers.
      - The three bit ops are **integer-only**; a float argument is a (non-
        catchable) type error, matching C++ Nix.
- [x] `ceil` (number) — smallest integer ≥ `number`, returned as an **int**
      (`i64`). Accepts int or float; an int passes through.
- [x] `floor` (number) — largest integer ≤ `number`, returned as an **int**.
      - Both `ceil` and `floor` return the integer type, not a float — relevant
        because the result may then flow into `add`/`toString` with int rules.

**Integer/float formatting parity.** When a number is later coerced to a string
(via `toString`, interpolation, or `derivationStrict` env coercion), the textual
form must match C++ Nix exactly: integers are plain decimal; floats use Nix's
float-to-string rendering (which is *not* Rust's `{}` Display and *not* full
round-trip `{:?}` — it must be matched against C++ Nix's printer). Float
rendering is a named harness target because a mis-rendered float in a derivation
env changes the `.drv` bytes.

---

## 3. Comparison and logic

- [x] `lessThan` (e1 e2) — `e1 < e2`, the *only* comparison primop; `>`, `<=`,
      `>=`, and `==`/`!=` ordering all desugar through it / through structural
      equality in the language core (see
      [language conformance](20-nix-language-conformance.md)).
      - Numeric: int/float mixed comparison promotes (`lessThan 1 1.5`).
      - Strings: bytewise lexicographic (matching the store-ordering rule in
        [derivation and store compatibility](11-derivation-and-store-compatibility.md) §6),
        **not** locale collation.
      - Lists: C++ Nix compares lists element-wise with `lessThan` (a relatively
        recent capability); this ordering feeds `builtins.sort` on lists of
        lists and must match. Comparing values of *incomparable* types throws.
      - This is the comparator semantics every `sort` without an explicit
        comparator relies on.

`true`, `false`, `null` exist both as keywords (language core) and as members of
the `builtins` set (§14); the logical operators `&&`, `||`, `!`, `->` are
language syntax, not builtins, and are covered in doc 20.

---

## 4. Strings

String primops must propagate **string context** exactly (see
[derivation and store compatibility](11-derivation-and-store-compatibility.md) §8
and §5 below). Unless noted, a string-producing primop **unions** the contexts
of its string inputs; context is string-granular, never byte-granular.

- [ ] `toString` (e) — coerce `e` to a string. The coercion rules are
      load-bearing and must match exactly:
      - string → itself (context preserved);
      - path → its path string (and, in a derivation context, copies to store /
        adds to `input_sources`);
      - int → decimal; float → Nix float rendering (§2);
      - `true` → `"1"`, `false` → `""`, `null` → `""`;
      - list → space-joined coercions of elements;
      - attrset with `__toString` → result of calling it; else attrset with
        `outPath` → coerce that;
      - a lambda/other → type error.
      - `toString` of a derivation attrset uses its `outPath` and carries that
        output's context (the dependency-threading path).
- [ ] `substring` (start len s) — substring of `s` from byte offset `start`,
      length `len`. **Byte offsets, not codepoints.**
      - `len` may exceed the remaining length (clamped to end, no error).
      - A `start` past the end yields `""`. Negative `start` throws; negative
        `len` means "to the end" in C++ Nix (verify against pinned version and
        pin the behavior).
      - Preserves the **entire** context of `s` (Nix does not slice context).
- [ ] `stringLength` (e) — length of `e` in **bytes** (after coercion to
      string), not codepoints.
- [ ] `replaceStrings` (from to s) — simultaneously replace each occurrence of
      `from[i]` with `to[i]` in `s`, left-to-right, longest-match-at-position
      first-listed-wins, non-overlapping, single pass.
      - The empty pattern `""` matches at every position (including end) and is
        a documented edge case used in nixpkgs; reproduce the exact insertion
        behavior.
      - Unions contexts of `s` **and** of every `to[i]` that gets used.
- [ ] `concatStringsSep` (separator list) — join `list` (coerced element-wise to
      strings) with `separator`.
      - Unions the separator's context and every element's context.
      - Element coercion follows `toString` rules (so a list element that is a
        derivation contributes its `outPath` + context).
- [ ] `splitVersion` (s) — split a version string into its component parts
      (digit runs and non-digit runs become elements; separators dropped).
      Returns a list of strings.
- [ ] `compareVersions` (s1 s2) — return `-1`, `0`, or `1` per Nix's version
      ordering algorithm (the same one `nix-env -u` uses).
      - The algorithm has specific rules for empty components and for `"pre"`
        sorting *before* the empty component; these are non-obvious and must be
        matched exactly (nixpkgs leans on it).
- [ ] `match` (regex str) — anchored full-string POSIX-ERE match. Returns `null`
      on no match, else a list of the capture groups (un-grouped capture → that
      element is `null`).
      - **Anchored**: the regex must match the *entire* string, not a substring.
      - Regex dialect is the host POSIX ERE engine in C++ Nix (`std::regex` with
        the ECMAScript-ish/`extended` flavor as Nix configures it). aos-nix must
        match this dialect's behavior on the patterns nixpkgs uses — a named
        risk, since Rust's `regex` crate differs in some corners. Pin via the
        differential harness; consider a POSIX-compatible engine if `regex`
        diverges.
- [ ] `split` (regex str) — split `str` by `regex`, returning an
      *interleaved* list: `[ text [groups] text [groups] … ]`, where the
      odd positions are lists of the capture groups of each separator match.
      - This interleaving shape is the surprising part and is exactly what
        nixpkgs' `lib.splitString`-adjacent code consumes; reproduce precisely.
      - Same regex-dialect caveat as `match`.
- [ ] `parseDrvName` (s) — split a derivation name `"foo-1.2"` into
      `{ name = "foo"; version = "1.2"; }` at the first dash that is followed by
      a digit. Edge cases (no version, leading digits) must match.
- [ ] `baseNameOf` (x) — the final path component of a coerced string/path.
      Trailing-slash and empty-string behavior must match. **String-granular**:
      operates on the string form; context is preserved.
- [ ] `dirOf` (s) — everything but the final component (the "directory" of a
      coerced string/path). On a path returns a path; on a string returns a
      string. Root/`.`/no-slash edge cases must match.

**Not builtins — do not implement under `builtins`** (see §17): `toLower`,
`toUpper`, `concatStrings`, `stringToCharacters`, `splitString`,
`hasPrefix`/`hasSuffix`, `optionalString`. These are **`lib`** functions
implemented *in Nix* on top of `replaceStrings`/`substring`/`stringLength`. They
must continue to work because they are *defined in nixpkgs*, but only by virtue
of the underlying real primops being correct — they are not entries in the
`builtins` set.

---

## 5. String-context primops

String context is the dependency graph hiding inside strings (see
[derivation and store compatibility](11-derivation-and-store-compatibility.md) §8
for the full model and the three deriving-path element kinds: constant/opaque,
single-output `!out!…`, and deep `=…`). These primops are the *explicit* context
manipulators; getting their bit-semantics wrong silently changes a derivation's
input set. Each gets adversarial differential coverage.

- [ ] `getContext` (s) — reflect `s`'s context into an inspectable attrset
      keyed by store path, each value `{ path = bool; allOutputs = bool;
      outputs = [ … ]; }`. The exact key/flag encoding must match so a
      round-trip through `appendContext` reproduces the same context.
- [ ] `hasContext` (s) — `true` iff `s` carries any context element. Cheap with
      our interned-bitset representation (see
      [derivation and store compatibility](11-derivation-and-store-compatibility.md) §8.3).
- [ ] `unsafeDiscardStringContext` (s) — same bytes, **empty** context. Used
      deliberately to name a store path without forcing it to be built. Must
      return a string equal byte-wise to `s` but with no context bits.
- [ ] `unsafeDiscardOutputDependency` (s) — downgrade `=`/deep (whole-closure)
      context elements to plain `!out!` single-output dependencies. Narrow,
      rare, but its exact effect on the bitset is parity-critical.
- [ ] `addDrvOutputDependencies` (s) — upgrade a *constant* element naming a
      `.drv` path into a *deep* (`=`) element. The dual of
      `unsafeDiscardOutputDependency`. Requires `s` to carry exactly one
      constant context element naming a `.drv`; error conditions must match.
      - Introduced relatively recently (Nix ≥ 2.16-era) as the supported
        replacement for context-manipulation hacks; note for the version pin.
- [ ] `appendContext` (s context) — merge a reflected context (the
      `getContext`-shaped attrset) back into `s`'s context. The inverse pairing
      with `getContext`; the merge must be a context **union**.
- [ ] `storePath` (path) — turn a path that is *already* in the store into a
      string with a single constant context element naming that path (so it
      becomes an `input_source`). Errors if the path is not a valid store path.
      - Disabled under pure-/restricted-eval; flag accordingly (§13, §16).
- [ ] `outputOf` (drv-ref output-name) — produce the deriving path string for a
      named output of a (possibly CA / not-yet-known) derivation reference,
      enabling "output of the output of" indirection for dynamic derivations.
      - **Experimental** (`dynamic-derivations`); generally **out of scope /
        stubbed** for the pinned AOS target unless the package set uses it (§17).
        If present in the pinned `builtins`, it must at least *exist* so
        `attrNames builtins` matches even if it errors when exercised.

The *general* string primops in §4 must also union contexts — that is where most
context flows in practice (`"${a}${b}"`, `concatStringsSep`, `replaceStrings`).
The §5 set is only the explicit manipulation surface.

---

## 6. Attribute sets

The dominating parity rule: **`attrNames` and the iteration order of any attrset
are SORTED by attribute name, bytewise** — the same deterministic collation that
[derivation and store compatibility](11-derivation-and-store-compatibility.md) §6
depends on and that [attribute sets and hidden classes](09-attribute-sets-hidden-classes-and-inline-caches.md)
commits to reproducing. Any primop that returns names/values in attr order must
emit them in this sorted order, not insertion order.

- [x] `attrNames` (set) — list of attribute names, **sorted bytewise**. The
      single most order-sensitive builtin; a mis-sort here propagates into
      `derivationStrict` env coercion order.
- [x] `attrValues` (set) — list of values in the **same sorted-by-name order**
      as `attrNames` (not insertion order). Must agree with `attrNames` exactly.
- [x] `getAttr` (s set) — `set.${s}`; throws if absent. Strict in `s` and the
      set spine.
- [x] `hasAttr` (s set) — `set ? ${s}` as a primop; `true`/`false`.
- [x] `removeAttrs` (set list) — `set` minus every name in `list`. Names not
      present are ignored (no error). Result order is the sorted remainder.
- [x] `listToAttrs` (list) — build an attrset from a list of
      `{ name = …; value = …; }`. **First occurrence wins** on duplicate names
      (C++ Nix keeps the first); reproduce that, not last-wins.
- [x] `intersectAttrs` (e1 e2) — attrset of the keys present in **both**, taking
      **values from `e2`**. (Direction is a classic confusion: the *names* come
      from the intersection, the *values* from the second argument.)
- [x] `catAttrs` (attr list) — for a list of attrsets, collect `set.${attr}`
      from each set **that has it**, in list order, skipping those that lack it.
- [ ] `mapAttrs` (f set) — apply `f name value` to each attribute, producing a
      new attrset with the same names. `f` is called lazily per value; forcing
      order follows demand on the result. Name set unchanged (so order unchanged).
- [ ] `zipAttrsWith` (f list) — given a list of attrsets, for each name that
      appears in any of them call `f name [values…]` where the list is the
      values from the sets that had that name, **in input-list order**. Returns
      one attrset over the union of names.
      - This *is* a `builtins` primop (sometimes mistaken for `lib`-only);
        `lib.zipAttrsWith` wraps it but the primop exists. Verify presence
        against the pinned `builtins` and pin the value-list ordering.
- [x] `functionArgs` (f) — (also listed under introspection §1) reflects a
      lambda's formal arguments; placed here too because nixpkgs uses it for
      attrset-driven auto-calling (`callPackage`).
- [ ] `unsafeGetAttrPos` (s set) — return `{ file; line; column; }` of where
      attribute `s` was defined in `set`, or `null`. Used by nixpkgs for error
      messages and `meta.position`.
      - The `file`/`line`/`column` values depend on source provenance tracking;
        for `.drv` parity it only matters if a derivation attribute is *derived*
        from a position (rare), but the primop must exist and return the same
        shape. Flag as a provenance-tracking requirement on the frontend
        ([frontend, parser, and IR](04-frontend-parser-and-ir.md)).

---

## 7. Lists

List primops are mostly pure structural transforms. Laziness is per-element:
`map`/`genList` build lists of thunks; `filter`/`foldl'`/`sort` force as needed.
Forcing order is observable and must match (see
[primops and the runtime ABI](10-primops-and-runtime-abi.md) §5.3 on `foldl'`).

- [x] `head` (list) — first element; throws on empty. Forces the spine, not the
      element (returns the element thunk).
- [x] `tail` (list) — all but the first; throws on empty.
- [x] `elemAt` (xs n) — zero-based index; throws out of range. Forces the list
      spine and `n`.
- [x] `length` (list) — element count. Forces only the spine.
- [x] `elem` (x xs) — membership by **structural equality**; forces elements as
      it scans (short-circuits on match). Equality semantics must match the
      language core's `==`.
- [x] `filter` (f list) — keep elements where `f elem` is `true`. Result order
      preserved. `f` forced per element.
- [x] `map` (f list) — list of `f elem` thunks; lazy in elements, strict in the
      argument list's spine.
- [x] `foldl'` (op nul list) — **strict** left fold: forces the accumulator at
      every step (its whole reason to exist over the non-strict `foldl`, which
      is *not* a builtin — `lib.foldr`/`foldl` are Nix-level). The worker/wrapper
      optimization keys off this strictness (see
      [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)).
- [x] `genList` (generator length) — `[ (generator 0) … (generator (length-1)) ]`,
      elements as thunks. Negative length throws.
- [x] `sort` (comparator list) — sort with a binary `comparator` (`a: b: bool`,
      true iff `a` strictly before `b`).
      - Nix's sort is a **stable** sort and the comparator-tie behavior is
        observable; the exact algorithm/stability must match C++ Nix or sorted
        lists that feed derivations diverge (named in
        [primops and the runtime ABI](10-primops-and-runtime-abi.md) §5.2).
      - With no/identity comparator semantics, falls back to `lessThan`-style
        ordering — pin exact behavior.
- [x] `concatLists` (lists) — flatten one level: concatenate a list of lists.
- [x] `concatMap` (f list) — `concatLists (map f list)`, but a single primop;
      `f` must return a list per element.
- [x] `all` (pred list) — `true` iff `pred` holds for every element;
      short-circuits on first `false`. Empty list → `true`.
- [x] `any` (pred list) — `true` iff `pred` holds for some element;
      short-circuits on first `true`. Empty list → `false`.
- [x] `partition` (pred list) — `{ right = [matching]; wrong = [non-matching]; }`,
      each preserving input order. (Key names are exactly `right`/`wrong`.)
- [x] `groupBy` (f list) — attrset grouping elements by the **string** key
      `f elem` returns; each value is the list of elements (input order) in that
      group. Result attr order is sorted by group-key (attrset rule §6).
- [ ] `genericClosure` (arg) — fixpoint/worklist primop. `arg` is
      `{ startSet = [ {key=…; …} … ]; operator = item: [ {key=…; …} … ]; }`;
      it transitively closes `startSet` under `operator`, **deduplicating by the
      `key` attribute**. The dedup-by-`key` and the work-order are precise and
      nixpkgs' module system depends on them; pin exactly.

There is **no** `builtins.remove`, `builtins.zipWith`, `builtins.reverse`, or
`builtins.range` — those are `lib`/`lib.lists` (§17). Do not add them under
`builtins`.

---

## 8. Encoding, parsing, and serialization

Byte-exact output is mandatory for `toJSON` (it feeds `__structuredAttrs` env
blobs and derivation attributes — see
[derivation and store compatibility](11-derivation-and-store-compatibility.md) §3.2).

- [ ] `toJSON` (e) — serialize `e` to a JSON string. **Byte-parity target.**
      - Object keys emitted in **sorted (attr) order** (§6); no insignificant
        whitespace beyond C++ Nix's exact formatting; number formatting matches
        the int/float rules (§2); strings escaped per Nix's JSON escaper (which
        is not necessarily `serde_json`'s — pin the escape set, especially for
        control characters and non-ASCII).
      - A value carrying string **context** can be serialized; whether context
        survives / is required to be discarded follows C++ Nix (it embeds the
        path text); the *bytes* are what the harness checks.
      - Forces `e` deeply (it must, to serialize).
      - An attrset with `__toString` or `outPath` follows the coercion rules,
        not a literal object dump — verify which wins.
- [ ] `fromJSON` (e) — parse a JSON string to a Nix value. Numbers become int or
      float per JSON syntax; objects become attrsets (duplicate-key behavior must
      match); result strings carry **no** context.
- [ ] `toXML` (e) — serialize `e` to Nix's XML plist-like format (the
      `nix-instantiate --xml` representation). Rarely used downstream but a real
      primop; must exist and match bytes if exercised.
- [ ] `fromTOML` (e) — parse a TOML string to a Nix value. nixpkgs uses this for
      `Cargo.toml`-driven derivations, so it is genuinely load-bearing.
      - Match C++ Nix's TOML parser behavior, including its handling of dates
        and the known assertion-failure edge cases (the bundled `toml11`
        quirks); pin via harness.
      - **There is NO `builtins.toTOML`** — only `fromTOML`. Do not implement a
        `toTOML`; it is a long-standing unfilled feature request, not a primop.
- [x] `seq` (e1 e2) — force `e1` to **WHNF** (shallow), then return `e2`.
      Strict only in `e1` to head-normal form.
- [x] `deepSeq` (e1 e2) — force `e1` **deeply** (recursively, fully), then return
      `e2`. The recursion order/termination must match (it is how nixpkgs forces
      errors out of lazy structures, e.g. after `tryEval`).

---

## 9. Hashing

Hashes here are SHA-2/MD/SHA-1 *content* hashes exposed to the language; they are
distinct from the SHA-256 store-path hashing that `nix-compat` owns (see
[derivation and store compatibility](11-derivation-and-store-compatibility.md) §9
on the three-hashes policy). Output is a hex string by default.

- [ ] `hashString` (type s) — hash the bytes of `s` with algorithm `type`.
      - Supported `type` values: `"md5"`, `"sha1"`, `"sha256"`, `"sha512"`. An
        unknown algorithm throws; the error/accepted-set must match.
      - Default output encoding is lowercase **hex**. (Other encodings are via
        `convertHash`, below — `hashString` itself returns hex.)
      - Hashes the raw bytes; if `s` carries context, the *bytes* are hashed (and
        the result string is context-free).
- [ ] `hashFile` (type p) — hash the *contents of the file at path `p`* with
      algorithm `type`. **Impure / eval-time effect** (reads the filesystem) —
      must be keyed into the incremental cache by the file's content hash (§13).
      - Same algorithm set as `hashString`.
- [ ] `convertHash` (args) — convert a hash between encodings/algorithms:
      `args = { hash; hashAlgo ? null; toHashFormat; }` with `toHashFormat` one
      of `"base16"`/`"nix32"`/`"base32"`/`"base64"`/`"sri"`. The `nix32`/base32
      alphabet is Nix's custom one (see
      [derivation and store compatibility](11-derivation-and-store-compatibility.md) §5.1).
      - Introduced Nix ≥ 2.19. Note for the version pin; if the pinned `nix`
        predates it, it is absent from `builtins` and must be absent here too.

---

## 10. IO and impure (eval-time effects)

**Every builtin in this section is an eval-time effect.** Its result is not a
pure function of the Nix expression — it depends on the filesystem, the
environment, or the clock. For the incremental cache to be sound, each such call
must be recorded as an explicit dependency edge and keyed into the cache so a
change to the underlying input invalidates exactly the memoized results that
observed it (see [the incremental evaluation cache](12-incremental-evaluation-cache.md),
requirement **R-10**). The keying table is §15.

Several of these are **gated** by evaluation mode: `--pure-eval` (flakes) and
`restrict-eval` / `--restrict-eval` disable filesystem and environment access;
`getEnv` returns `""` in pure mode; etc. aos-nix must reproduce the *same*
gating as the pinned `nix` so an expression that errors (or returns `""`) under
a given mode does so identically.

- [ ] `readFile` (path) — return the file's contents as a string (no context).
      Effect: file content. Non-UTF-8 bytes pass through (string is a byte
      string — see [value representation](05-value-representation.md)). Cache key
      = content hash of the file.
- [ ] `readDir` (path) — attrset mapping each entry name to its type string
      (`"regular"`, `"directory"`, `"symlink"`, `"unknown"`). Effect: directory
      listing. Cache key = a digest of the (name,type) entries.
- [ ] `pathExists` (path) — `true` iff the path exists (following symlinks).
      Effect: a stat. Cache key = existence + (arguably) the resolved target;
      pin to C++ Nix's observable behavior.
- [ ] `readFileType` (p) — the type string of `p` alone (`"regular"`,
      `"directory"`, `"symlink"`, `"unknown"`) without listing a directory.
      - Introduced Nix ≥ 2.14. Effect: a stat/lstat. Note for the version pin.
- [ ] `getEnv` (s) — value of environment variable `s`, or `""` if unset.
      Effect: the environment. **Returns `""` under pure-eval** regardless of the
      real environment — reproduce this gating. Cache key = the variable's value.
      - nixpkgs reads `NIX_PATH`-adjacent vars and `IN_NIX_SHELL`-style vars via
        this; the empty-in-pure-mode behavior is what keeps pure eval
        reproducible.
- [ ] `currentTime` (value) — the Unix time at the *start of evaluation* (a
      constant for the whole eval, not re-read per call). Effect: the clock.
      **Not soundly cacheable**; nixpkgs avoids it in pure paths. aos-nix must
      treat any memo that observed `currentTime` as non-reusable across runs
      (or refuse to persist it) — see §13/§15.
- [ ] `currentSystem` (value) — the host system string (`"x86_64-linux"`).
      Effect: build-time configuration, but **constant per evaluator config**.
      Cache key = the configured system string. Disabled under pure-eval (flakes
      pass `system` explicitly).
- [ ] `trace` (e1 e2) — print `e1` (to stderr) and return `e2`. Effect: a
      side-effecting print; *pure* in its return value. Parity matters only for
      *which* traces fire (a function of forcing order), not the text, for `.drv`
      parity — but the harness still compares trace firing because divergent
      forcing order is a bug signal (see
      [primops and the runtime ABI](10-primops-and-runtime-abi.md) §2.3).
- [ ] `traceVerbose` (e1 e2) — like `trace` but only prints when verbose tracing
      is enabled; return value identical to `e2` either way.
- [ ] `warn` (e1 e2) — print a warning for `e1` and return `e2` (and, depending
      on settings, may abort if warnings-as-errors is set). Introduced Nix
      ≥ 2.23; note for the version pin and reproduce the abort-on-strict-warn
      gating.
- [ ] `break` (v) — drop into the debugger REPL when `--debugger` is active,
      otherwise return `v` unchanged. Effect: interactive only; in non-debugger
      (the AOS batch) mode it is the identity and must be transparent.

`getFlake` and `exec` are also effectful but are **out of scope / stubbed** —
see §13 and §17.

---

## 11. Paths and fetching

These compute store paths at *evaluation* time (the eval-side store-path hashing
that [derivation and store compatibility](11-derivation-and-store-compatibility.md) §2
carves out as in-scope: `builtins.path`, `filterSource`, `toFile`, fixed-output
fetchers). They are effects (they read sources and/or the network) **and**
produce strings with store-path context. Fetchers are gated under restricted/pure
eval (network access is disabled unless explicitly allowed).

- [ ] `path` (args) — `{ path; name ? baseNameOf path; filter ? (p: t: true);
      recursive ? true; sha256 ? null; }` — copy a source path into the store
      (optionally filtered) and return its store path string with context.
      - The NAR/store-path hashing must match (`nix-compat`); the `filter`
        predicate is called `path -> type -> bool` per entry and its calls/order
        are observable. If `sha256` is given it is a fixed-output assertion.
      - This is the modern, named-argument superset of `filterSource`.
- [ ] `filterSource` (e1 e2) — `path { path = e2; filter = e1; }` essentially:
      copy `e2` into the store keeping only entries for which
      `e1 path type` is true. Older API; still used. Same store-path hashing.
- [ ] `toFile` (name s) — write string `s` to a store file named `name`,
      returning its store path string with constant context.
      - `s` must **not** carry context that references a derivation output
        (you cannot `toFile` something depending on a build) — the error
        condition must match. Store-path computed by the `text` method
        ([derivation and store compatibility](11-derivation-and-store-compatibility.md) §5.1).
- [ ] `fetchurl` (arg) — fetch a URL to the store; `arg` is a URL string or
      `{ url; sha256 ? …; name ? …; }`. **Fixed-output** when a hash is given, so
      its output store path is known at eval time (the foundational
      reproducibility property). Network effect; gated under restricted eval.
- [ ] `fetchTarball` (args) — fetch and **unpack** a tarball; `args` is a URL or
      `{ url; sha256 ? …; name ? …; }`. Returns the unpacked store path. Note the
      `sha256` here is the hash of the *unpacked* tree (`r:sha256`), unlike
      `fetchurl`'s flat hash — a frequent confusion to pin.
- [ ] `fetchGit` (args) — fetch a git repo; `{ url; rev ? …; ref ? …;
      submodules ? …; shallow ? …; allRefs ? …; }`. Returns
      `{ outPath; rev; shortRev; revCount; lastModified; … }`. The exact returned
      attrset shape and the dirty-tree handling must match.
- [ ] `fetchTree` (input) — the generic flake-style fetcher dispatching on a
      `type` (`"github"`, `"git"`, `"tarball"`, `"path"`, …). Returns a tree
      attrset with `outPath` and lock metadata.
      - Stabilized as non-experimental in Nix ≥ 2.19 (was experimental before).
        Tied to the flakes machinery; treat as **conditional scope** — implement
        only if the pinned AOS package set / flake inputs require it, else stub
        to existence (§17).
- [ ] `fetchClosure` (args) — substitute an entire store-path closure from a
      binary cache by content address (`{ fromStore; fromPath; toPath ? …; }`).
      Experimental (`fetch-closure`). **Out of scope / stubbed** unless the
      pinned set uses it (§17).
- [ ] `fetchMercurial` (args) — hg analogue of `fetchGit`. Almost never used in
      AOS; implement to existence, likely **stubbed** beyond presence (§17).
- [ ] `findFile` (search-path lookup-path) — the engine behind `<nixpkgs>`-style
      angle-bracket lookup: resolve `lookup-path` against `search-path`
      (the `NIX_PATH`/`-I` entries). Returns the resolved path.
      - For byte-identical `.drv` output, `<nixpkgs>` must resolve to the **same
        concrete store path** C++ Nix resolves; honor identical `NIX_PATH`/`-I`
        precedence and positive/negative lookup caching (see
        [primops and the runtime ABI](10-primops-and-runtime-abi.md) §6.4). A
        wrong resolution is a silent catastrophic divergence.
      - `nixPath` (§14) is the reflected value of the search path.
- [ ] `placeholder` (output) — return the stable placeholder string Nix uses for
      a not-yet-known output path (`/<hash>` form) so build scripts can reference
      `$out` before it exists. The placeholder bytes are *hashed* into
      derivations, so they must be byte-identical to C++ Nix's scheme (see
      [derivation and store compatibility](11-derivation-and-store-compatibility.md) §5.3).
- [ ] `storePath` (path) — (also §5) assert a path is in the store and return it
      as a context-carrying string; gated under restricted/pure eval.
- [ ] `storeDir` (value) — the store directory string (`"/nix/store"`). A
      constant; feeds path computation. (Listed also in §14 as a constant.)
- [ ] `toPath` (s) — **deprecated** coercion of a string to a path; retained for
      compatibility. Implement to match (likely an alias-ish to coercion) only if
      present in the pinned `builtins`; otherwise omit.

---

## 12. Derivations

This is the heart of compatibility; the full algorithm, ATerm format, hashing,
ordering, and context partition live in
[derivation and store compatibility](11-derivation-and-store-compatibility.md).
Here we enumerate only the *builtin surface* and the attributes it consumes.

- [ ] `derivationStrict` (attrs) — **the real primop.** Forces `attrs` eagerly,
      extracts the special attributes, coerces the rest to env vars in
      deterministic attr order (accumulating context), partitions context into
      `input_derivations`/`input_sources`, computes drv path and output paths via
      `nix-compat`, writes the `.drv`, and returns
      `{ drvPath; outputs = { out = …; … }; }`. This is the byte-parity gate.
      - Special attributes consumed (not emitted as plain env): `name`,
        `system`, `builder`, `args`, `outputs`, `__structuredAttrs`,
        `__ignoreNulls`, `outputHash`, `outputHashAlgo`, `outputHashMode`,
        `__contentAddressed`, and the `allowed`/`disallowedReferences` family.
      - **`outputs`**: default `["out"]`; multiple outputs (`["out" "dev" …]`)
        produce one path per output, each back-patched into both `outputs` and
        the corresponding `$out`/`$dev` env var.
      - **Fixed-output**: `outputHash` + `outputHashAlgo`
        (`md5`/`sha1`/`sha256`/`sha512`) + `outputHashMode` (`flat`/`recursive`,
        the latter NAR-hashed and rendered `r:sha256`). Output path determined by
        the declared hash alone (stable across input changes).
      - **`__contentAddressed = true`**: CA/floating outputs; output `path` left
        empty at eval time, only `ca_hash` method recorded
        ([derivation and store compatibility](11-derivation-and-store-compatibility.md) §5.4).
        Experimental at the *Nix-feature* level (`ca-derivations`), but **in scope
        and required for aos-nix from the start** (a deliberate design choice) —
        its eval-time semantics and `.drv` encoding are gated, not deferred. Only
        *dynamic* derivations (`outputOf`/`dynamic-derivations`) remain
        conditionally scoped.
      - **`__structuredAttrs = true`**: non-special attrs serialized into a JSON
        blob (the `__json` env var) with its own ordering/escaping — a nested
        wire format to match.
      - **`__ignoreNulls = true`**: `null`-valued attributes are omitted from the
        env entirely.
      - Input-addressed is the **default** (no `outputHash`, no
        `__contentAddressed`): output path = `hashDerivationModulo`-derived
        (§5.2/§5.3 of doc 11).
- [ ] `derivation` (attrs) — **the `lib`/corepkgs wrapper**, not a primop in the
      same sense: it is a thin Nix function (`derivation.nix`) that fills
      defaults (`system`, etc.), calls `derivationStrict`, and reshapes the
      result into the familiar derivation attrset (with `outPath`, `drvPath`,
      `type = "derivation"`, the `outputs` attrs, `all`, etc.).
      - Exposed in the **global scope** as well as `builtins.derivation`. Its
        behavior is determined entirely by `derivationStrict` plus the wrapper
        logic; the wrapper itself is Nix code shipped with Nix (so its *exact*
        text for the pinned version matters — a divergence between our bundled
        `derivation.nix` and the pinned one changes results). Pin the wrapper
        source to the reference version.
      - The historical `derivation` vs `derivationStrict` `outputs`-coercion
        discrepancy (NixOS/nix#7569) is a known wart to reproduce, not fix.
- [ ] `outputOf` (drv-ref output-name) — (also §5) deriving-path indirection for
      dynamic derivations; experimental, conditional scope (§17).
- [ ] `unsafeDiscardOutputDependency` / `addDrvOutputDependencies` — (the §5
      context primops) are the explicit knobs nixpkgs uses to shape what a
      derivation depends on; relisted here as derivation-adjacent.

**IFD (import-from-derivation).** `import (someDerivation)` (or `readFile`/
`readDir` on a derivation output path) forces the derivation's output, which
**requires the derivation to be built** before evaluation can continue. aos-nix
is eval-only and does not build; at an IFD boundary it must hand the `.drv` to
the realiser (the `NixEval`/`instantiate` seam in
[integration with AOS](14-integration-with-aos.md), realisation owned by
RFC-0005), block on the realised output, then resume evaluation reading the
built path. The *result* is keyed into the incremental cache by the realised
output path's hash (§13/§15). IFD parity = forcing the same builds in the same
places C++ Nix would.

---

## 13. Control, errors, and meta

- [x] `throw` (s) — raise a **catchable** evaluation error with message `s`.
      Caught by `tryEval`. Strict in `s`.
- [x] `abort` (s) — raise a **non-catchable** fatal error with message `s`.
      **Not** caught by `tryEval` (verified: the whole point of `abort` is that
      it is not caught). Aborts the evaluation.
- [x] `tryEval` (e) — force `e` to **WHNF** (shallow!) and return
      `{ success = true; value = e; }`, or `{ success = false; value = false; }`
      if forcing raised a **catchable** error.
      - Catches: `throw`, `assert` failures (and other "catchable" errors —
        builtin type errors are generally **not** catchable, matching C++ Nix).
      - Does **not** catch: `abort`. Verified against the manual.
      - **Shallow**: `tryEval { x = throw "boom"; }` succeeds because the thunk
        `x` is never forced. Pair with `deepSeq` to force deeply. This shallow
        behavior must be reproduced exactly (it is observable and nixpkgs relies
        on it).
      - In the JIT tiers this is a catch-frame runtime symbol, not C++-style
        unwinding (see [primops and the runtime ABI](10-primops-and-runtime-abi.md) §5.4).
- [x] `assert` — **language syntax**, not a builtin (`assert cond; body`). Listed
      here only to record its `tryEval` interaction: a failed assertion is a
      catchable error. The syntax is covered in
      [language conformance](20-nix-language-conformance.md).
- [ ] `addErrorContext` (s e) — evaluate `e`, and if it raises an error, prepend
      `s` to the error's context trace. Affects error *messages*, not values;
      parity matters only for error-message-shaped tests, but the primop must
      exist (nixpkgs `lib` wraps it for `addErrorContext`-style annotations).
- [ ] `import` (path) — parse and evaluate the file at `path` (or
      `path/default.nix` for a directory) in a **fresh** global scope and return
      its value. A real primop in `builtins` and mirrored into global scope. The
      *language-level* scope-isolation, `default.nix` resolution, per-path
      memoization, and IFD semantics live in
      [language conformance](20-nix-language-conformance.md) §13; the builtin-level
      parity hazards are the **memoization cache key** (canonicalized resolved
      path — single evaluation shared across all `import`s of the same path) and
      the IFD trigger (importing a derivation output forces a build, §12). Caches
      results, *unlike* `scopedImport`.
- [ ] `scopedImport` (attrs path) — like `import` but injects `attrs` into the
      imported file's *global* scope (overriding/shadowing `builtins`, `derivation`,
      etc.); it backs nixpkgs' `import` shadowing. **In scope.** Distinct parity
      note: it **does not memoize** (each call re-evaluates), unlike `import` —
      see [primops and the runtime ABI](10-primops-and-runtime-abi.md) §6.1 and §17.
- [ ] `trace` / `traceVerbose` / `warn` / `break` — (effectful, listed §10).

---

## 14. Version and identity constants

These are *values* in the `builtins` set (not functions). They are version- and
config-sensitive, and several are **parity decisions** because nixpkgs branches
on them.

- [ ] `builtins` (set) — the builtins set reflects itself: `builtins.builtins`
      is `builtins`. Its membership and **attr order** must equal the pinned
      `nix`'s (the differential gate; see
      [primops and the runtime ABI](10-primops-and-runtime-abi.md) §4.4).
- [ ] `true` / `false` / `null` — present both as language keywords and as
      members of `builtins`. Must exist as members so `attrNames builtins`
      matches.
- [x] `nixVersion` (string) — the reported Nix version, e.g. `"2.32.0"`.
      **PARITY DECISION (flag):** nixpkgs has version-gated code paths
      (`lib.versionAtLeast builtins.nixVersion …`). To take the *same* branches
      the pinned C++ Nix takes, **aos-nix must report the pinned C++ Nix version
      string verbatim**, not an aos-nix version. Reporting our own version would
      silently flip feature gates and diverge `.drv` output. Decision: spoof the
      pinned version; record it in [the decision register](19-decision-register.md).
- [x] `langVersion` (integer) — the Nix *language* version (an integer, e.g.
      `6`). **Same parity decision** as `nixVersion`: report the pinned value so
      any `langVersion`-gated code matches.
- [ ] `nixPath` (list) — reflected `NIX_PATH` search entries (list of
      `{ prefix; path; }`). Must match the configured/pinned search path so
      `<nixpkgs>` resolution and any nixpkgs introspection of `nixPath` agree.
- [ ] `currentSystem` (string) — (also §10) the host system; constant per config.
- [ ] `currentTime` (integer) — (also §10) start-of-eval Unix time; the one
      genuinely non-deterministic constant.
- [ ] `storeDir` (string) — (also §11) `"/nix/store"`.

**Decision summary (flagged for [decision register](19-decision-register.md)):**
`nixVersion` and `langVersion` are **spoofed to the pinned C++ Nix values**.
This is not optional cosmetics — it is required for feature-gate parity and
therefore for `.drv` parity.

---

## 15. Impure builtins and incremental-cache keying

This table is the contract between this layer and
[the incremental evaluation cache](12-incremental-evaluation-cache.md) (R-10):
every effectful builtin records a dependency edge so a memoized eval result is
invalidated when, and only when, the observed input changes. Pure builtins are
omitted (they are keyed by their argument value hashes like any expression).

| Builtin | Effect observed | Cache key / invalidation trigger | Mode gating |
|---|---|---|---|
| `readFile` | file contents | content hash of the file bytes | restrict/pure: path must be allowed |
| `readDir` | directory entries | digest of sorted (name,type) entries | restrict/pure: path allowed |
| `pathExists` | path stat | existence boolean (+ resolved target) | restrict/pure: path allowed |
| `readFileType` | path lstat | the type string | restrict/pure: path allowed |
| `hashFile` | file contents | the file content hash (== the result) | restrict/pure: path allowed |
| `path` / `filterSource` | source tree | NAR/store-path hash of the copied tree | network/path gating |
| `getEnv` | env variable | the variable's current value | **pure-eval: forced to `""`** |
| `currentSystem` | evaluator config | the configured system string | disabled under pure-eval |
| `currentTime` | wall clock | **not soundly cacheable**: taint the memo; do not persist a result that observed it | n/a |
| `fetchurl` | network (FOD) | the declared `sha256` (fixed-output: stable) | restrict-eval: must allow URL |
| `fetchTarball` | network (FOD) | the declared `sha256` of the unpacked tree | restrict-eval gating |
| `fetchGit` | network/git | `(url, rev)`; dirty-tree → tainted | restrict-eval gating |
| `fetchTree` | network | the locked-input narHash | pure-eval requires locked input |
| `fetchClosure` | binary cache | `fromPath` content address | experimental |
| `findFile` | NIX_PATH lookup | resolved store path (+ negative cache) | `<...>` disabled in pure-eval |
| `import` (of impure path) | file contents | content hash of imported file | inherits path gating |

`currentTime` is the one true hazard: any value derived from it makes a memo
non-reusable across runs. nixpkgs avoids `currentTime` on pure-eval paths
(flakes forbid it), which is why the AOS package set is cacheable in practice;
aos-nix must *detect* a `currentTime` dependency and refuse to persist that memo
rather than silently serve a stale time. See
[the incremental evaluation cache](12-incremental-evaluation-cache.md) §R-10 for
the full edge model.

---

## 16. The pinned-version contract

The authoritative builtin set is **whatever the single pinned open-source C++ Nix
version reports**. Concretely:

- [ ] The exact `builtins.attrNames builtins` of the pinned `nix` is captured as
      a golden fixture; the harness fails if aos-nix's set differs in membership
      or order.
- [ ] Every builtin whose existence is version-gated (noted inline above:
      `convertHash` ≥ 2.19, `readFileType` ≥ 2.14, `addDrvOutputDependencies`
      ≥ 2.16-era, `warn` ≥ 2.23, `fetchTree` stabilized ≥ 2.19) is present **iff**
      the pinned version includes it.
- [x] `nixVersion` / `langVersion` are spoofed to the pinned values (§14).
- [ ] Experimental-feature-gated builtins (`fetchClosure`, `outputOf`,
      `fetchTree` where still experimental, CA-derivation attributes) follow the
      pinned version's *enabled experimental features* — present and functional
      only if the pinned config enables them, otherwise present-but-erroring or
      absent exactly as the pinned `nix` behaves.

Bumping the pinned Nix version is a deliberate, harness-revalidated event (it can
change the builtin set, the wrapper `derivation.nix`, float formatting, or a
hash-modulo detail). It is tracked in
[roadmap and risks](17-roadmap-and-risks.md) and
[the decision register](19-decision-register.md).

---

## 17. Out of scope, stubbed, or "lib not builtins"

Honesty about the boundary, to prevent the fabrication class of error.

**Flake / experimental machinery — conditional scope or stubbed to existence.**
These exist in recent `builtins` but are tied to flakes or experimental features.
For the AOS target (a pinned, non-flake-centric from-source set) they are
implemented only if the pinned package set exercises them; otherwise they are
present in the `builtins` set (so `attrNames` matches) but error when called,
exactly mirroring how the pinned `nix` behaves with the relevant experimental
feature disabled:

- [ ] `getFlake` (args) — fetch and evaluate a flake. Flakes; **stubbed/scoped**.
- [ ] `parseFlakeRef` (flake-ref) / `flakeRefToString` (attrs) — flake-ref
      string ↔ attrset. Flakes; **stubbed/scoped**.
- [ ] `fetchTree` (input) — flake fetcher; **conditional** (§11).
- [ ] `fetchClosure` (args) — `fetch-closure`; **stubbed/scoped** (§11).
- [ ] `outputOf` (…) — `dynamic-derivations`; **stubbed/scoped** (§5/§12).
- [ ] `fetchMercurial` (args) — present-but-likely-unexercised (§11).
- [ ] `scopedImport` (attrs path) — a real primop (it backs nixpkgs' `import`
      shadowing). **In scope**, but called out here because it deliberately
      does **not** memoize (unlike `import`); see
      [primops and the runtime ABI](10-primops-and-runtime-abi.md) §6.1. Not
      stubbed — listed to flag the memoization asymmetry.
- [ ] `exec` — runs an external command during evaluation. Gated behind
      `--allow-unsafe-native-code` / the `exec` capability and disabled in
      restricted/pure eval. nixpkgs does not use it on the build path. **Out of
      scope / stubbed**; present only if the pinned `builtins` exposes it, and
      then erroring under the AOS eval mode exactly as upstream does.
- [ ] `toPath` (s) — **deprecated**; implement only if present in the pinned set
      (§11).

**`lib`, NOT `builtins` — must NOT appear in the `builtins` set.** These are
nixpkgs `lib` functions implemented in Nix on top of real primops. They work
because the primops are correct; they are *not* primops:

- [ ] `toLower` / `toUpper` — `lib.strings.toLower`/`toUpper` (built on
      `replaceStrings`). **Verified: not builtins.** (Past errata flagged these
      as builtins — they are not.)
- [ ] `toTOML` — **does not exist at all** (only `fromTOML` is a builtin).
      Verified: a long-standing unimplemented feature request, never a primop.
- [ ] `concatStrings`, `stringToCharacters`, `splitString`, `hasPrefix`,
      `hasSuffix`, `optionalString`, `removePrefix`, `removeSuffix`,
      `escapeShellArg`, `versionAtLeast`/`versionOlder` — all `lib.strings` /
      `lib` (the latter built on `compareVersions`). Not builtins.
- [ ] `foldr`, `foldl` (non-strict), `reverse`, `range`, `remove`, `zipWith`,
      `flatten`, `unique`, `last`, `init`, `take`, `drop`, `count`, `imap0`,
      `forEach`, `optionals` — all `lib.lists` / `lib`. The **only** fold builtin
      is the strict `foldl'`; the **only** list builtins are those in §7.
- [ ] `mapAttrsToList`, `filterAttrs`, `recursiveUpdate`, `attrByPath`,
      `optionalAttrs`, `mapAttrs'`, `genAttrs`, `nameValuePair` — all `lib.attrsets`.
      The builtin attrset surface is exactly §6.
- [ ] `id`, `const`, `flip`, `composeManyExtensions`, `pipe`, `fix`,
      `makeExtensible` — all `lib` / `lib.trivial`. Not builtins.
- [ ] `importJSON`, `importTOML` — `lib` wrappers around
      `fromJSON`/`fromTOML` + `readFile`. Not builtins.

The discriminating test, applied to every candidate: **does it appear in
`builtins.attrNames builtins` of the pinned `nix`?** If not, it is `lib` (or
fictional) and must not be a primop in aos-nix.

---

## 18. The compatibility-critical short list

A consolidated "if these are wrong, the gate is red" list, each with adversarial
differential coverage (cross-referenced to the hazards in
[derivation and store compatibility](11-derivation-and-store-compatibility.md) §6
and [primops and the runtime ABI](10-primops-and-runtime-abi.md) §8):

- [ ] `derivationStrict` — env coercion order, context partition, hash-modulo,
      output back-patching, `__structuredAttrs`/`__ignoreNulls`/fixed-output/CA.
- [ ] `toJSON` — key order, number/float formatting, escape set, deep forcing.
- [ ] `hashString` / `hashFile` / `convertHash` — algorithm set, hex/base32
      output, the Nix base32 alphabet.
- [ ] String-context primops (§5) — every union/discard/upgrade bit.
- [ ] String coercion (`toString`, interpolation, `concatStringsSep`,
      `replaceStrings`) context union.
- [ ] `attrNames` / `attrValues` / `mapAttrs` / `groupBy` sorted-by-name order.
- [ ] `sort` stability and tie-breaking; `lessThan` cross-type/list ordering.
- [ ] `compareVersions` / `splitVersion` / `parseDrvName` exact algorithms.
- [ ] `match` / `split` regex dialect (named risk vs. Rust `regex`).
- [ ] `div` truncate-toward-zero; int/float promotion and float rendering.
- [x] `listToAttrs` first-wins; `intersectAttrs` values-from-second.
- [x] `tryEval` catchability (throw/assert yes, abort no) and shallowness.
- [ ] `findFile` / `<nixpkgs>` resolution to the identical store path.
- [ ] `placeholder` byte-identical placeholder scheme.
- [ ] `nixVersion`/`langVersion` spoofing for feature-gate parity.
- [ ] `builtins` set membership and order.

---

## 19. Summary

The builtin surface is on the order of ~110–130 named entries in the pinned
`nix`'s `builtins` set (the exact count is the pinned version's
`builtins.attrNames builtins` golden fixture, §16 — recent manuals list ~127).
aos-nix implements every one as plain Rust on the uniform ABI
([primops and the runtime ABI](10-primops-and-runtime-abi.md)), with
`derivationStrict` delegating format work to `nix-compat`
([derivation and store compatibility](11-derivation-and-store-compatibility.md))
and the dozen effectful builtins keyed into the incremental cache
([the incremental evaluation cache](12-incremental-evaluation-cache.md) §R-10).
The conformance bar is byte-identical `.drv` output, enforced by the differential
harness over the full AOS closure
([differential testing and benchmarking](15-differential-testing-and-benchmarking.md)),
never by isolated unit tests. The authoritative set is the pinned version's
`attrNames builtins`; `nixVersion`/`langVersion` are spoofed to match it so
feature gates take identical branches. Flake/experimental builtins are
conditionally scoped or stubbed-to-existence; `toLower`/`toUpper`/`toTOML`/the
`lib.*` families are explicitly **not** builtins and are excluded.

---

## References

Verified against primary sources during authoring (June 2026):

- Nix Reference Manual — **Built-ins** (the authoritative builtins reference;
  source for the §1–§14 signatures and the full name list):
  <https://nix.dev/manual/nix/2.32/language/builtins> (and adjacent pinned
  versions: <https://nix.dev/manual/nix/2.34/language/builtins>,
  <https://nix.dev/manual/nix/2.30/language/builtins.html>)
- Nix Reference Manual — **String context** (deriving-path element kinds;
  `getContext`/`hasContext`/`unsafeDiscardStringContext`/
  `addDrvOutputDependencies`/`appendContext`):
  <https://nix.dev/manual/nix/2.32/language/string-context>
- Nix Reference Manual — **Advanced Attributes** (`__structuredAttrs`,
  `__ignoreNulls`, `outputHash`/`outputHashAlgo`/`outputHashMode`,
  `__contentAddressed`):
  <https://nix.dev/manual/nix/2.18/language/advanced-attributes.html>
- Nix Reference Manual — **Import From Derivation** (IFD forces a build):
  <https://nix.dev/manual/nix/2.34/language/import-from-derivation>
- `tryEval` catchability (catches `throw`/`assert`, **not** `abort`; shallow
  forcing) — manual + issue discussion:
  <https://nix.dev/manual/nix/2.34/language/builtins.html?highlight=tryEval> and
  <https://github.com/NixOS/nix/issues/356>
- **No `builtins.toTOML`** (feature requests, never implemented; `fromTOML`
  exists): <https://github.com/NixOS/nix/issues/2967> and
  <https://github.com/NixOS/nix/issues/3929>
- `toLower`/`toUpper` are **`lib`**, not builtins (`lib.strings`):
  <https://github.com/NixOS/nixpkgs/blob/master/lib/strings.nix> and
  <https://github.com/NixOS/nix/issues/4596>
- `readFileType` result strings (`directory`/`regular`/`symlink`/`unknown`):
  <https://nix.dev/manual/nix/2.30/language/builtins.html>
- `src/libexpr/primops.cc` (reference forcing order / exact semantics for every
  primop): <https://github.com/NixOS/nix/blob/master/src/libexpr/primops.cc>
- `derivation` vs `derivationStrict` `outputs` discrepancy (a wart to reproduce):
  <https://github.com/NixOS/nix/issues/7569>
- Snix / Tvix prior art (catchable-error model behind `tryEval`; `nix-compat`):
  <https://snix.dev/docs/components/eval/catchable-errors/> and
  <https://snix.dev/docs/components/eval/builtins/>
