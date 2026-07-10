# RFC-0007 - Nix language conformance checklist

This document is the **exhaustive, tickable inventory of every Nix *language*
feature, semantic rule, and edge case** aos-nix must reproduce to reach
byte-for-byte parity with the pinned open-source C++ Nix release AOS builds
against. It is two artifacts at once:

1. an **implementer's checklist** — each `- [ ]` is a unit of work the evaluator
   front end and core must land, ticked when it is implemented *and* differentially
   verified; and
2. a **conformance-suite enumeration** — every item below is a behavior the
   conformance corpus (see
   [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
   §3) and the `.drv`-diff acceptance gate (see
   [compatibility constraints](02-compatibility-constraints.md) §7) must exercise.

The scope here is the **language**: lexing, parsing, scoping, coercions,
operators, evaluation semantics, laziness, equality, and error classes. The
**builtins / primops catalog** (`builtins.*`, `derivationStrict`, `import`,
`map`, `genList`, the string-context primops, etc.) is owned by
[builtins conformance](21-builtins-conformance.md) and is **not** duplicated
here; where a language rule is observed *through* a builtin, this document names
the builtin and defers its full contract to doc 21.

## How to read this checklist

- **Parity bar.** Every item is governed by the
  [compatibility constraints](02-compatibility-constraints.md) contract: a
  technique or behavior is correct iff it is *observably indistinguishable* from
  C++ Nix at the `.drv` boundary. Where a language rule has a subtle edge, the
  one-line note states the exact rule and the failure mode.
- **The target is a single pinned C++ Nix version.** Nix has no specification;
  the reference implementation *is* the spec, quirks included (see
  [compatibility constraints](02-compatibility-constraints.md) §1.3). Every
  "verify against pinned Nix" tag below means: confirm the behavior against the
  exact rev recorded in
  [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
  §9 Q1, not against the manual's prose, which lags the implementation.
- **aos-nix is eval-only.** It parses `.nix` and lazily evaluates to a `.drv`
  graph; it never builds (see
  [compatibility constraints](02-compatibility-constraints.md) §1.1). Items that
  touch the store (path coercion, import-from-derivation) are about *what the
  evaluator computes and hands to the store layer*, not about realisation.
- **Eval errors are observable.** Error/no-error parity is part of the gate (see
  [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
  §2.1). Error *class* parity is in scope; error *text* parity is best-effort
  (doc 15 §3.3). Items that must error are tagged **must-error**.

---

## 1. Lexical structure

The tokenizer must accept exactly the token set C++ Nix accepts and reject the
rest at parse time (`parse-fail-*` conformance cases).

- [x] **Identifiers** — match `[a-zA-Z_][a-zA-Z0-9_'-]*`; first char is a letter
      or `_`, subsequent chars may include `'` (prime) and `-` (hyphen). Verify
      the exact allowed set against pinned Nix (the trailing `'`/`-` are easy to
      miss and `lib` uses primed names like `x'`).
- [x] **Keywords** — `assert`, `else`, `if`, `in`, `inherit`, `let`, `or`,
      `rec`, `then`, `with`. Note `or` is a *contextual* keyword: it is the
      default-value marker in attribute selection (`a.b or d`) and is accepted
      in pinned Nix 2.24 as an attribute path segment / binding name, plus as a
      bare unparenthesized application argument (`f or`), but not as a primary
      expression (`or`, `(or)`, `[ or ]`), lambda parameter, or formal-set name.
- [x] **Integer literals** — signed 64-bit (`i64`). A bare literal is a sequence
      of digits; a leading `-` is the negation *operator*, not part of the
      literal (precedence level 3, §6). No hex/octal/binary literals, no digit
      separators, no `0x`. Verify against pinned Nix.
- [x] **Float literals** — IEEE-754 double. Pinned Nix 2.24 accepts forms such
      as `1.0`, `.5`, `1.`, `1.e10`, and `1.5e-3`. A float is produced when a
      `.` is present; an exponent may then follow. Bare-exponent spellings
      without a dot (`1e10`, `3E8`) are not floats in the pinned version: they
      split as an integer followed by an identifier (`1` `e10`, `3` `E8`).
- [x] **Boolean literals** — `true` and `false` are *not* keywords; they are
      identifiers bound in the global `builtins` scope. The parser does not
      special-case them — shadowing `true` with a `let` binding is legal and
      observable. Note this and reproduce it.
- [x] **`null`** — likewise a global identifier (`builtins.null`), not a keyword.
- [x] **Line comments** — `#` to end of line.
- [x] **Block comments** — `/* ... */`, **non-nesting** (the first `*/` closes).
      Verify the non-nesting rule against pinned Nix.
- [x] **Whitespace** — space, tab, newline, CR are insignificant between tokens
      (significant *inside* string literals, §3). No layout/offside rule.
- [x] **No semicolon statement terminators** — `;` is a separator only inside
      `let`/attrset bindings and after `assert`/`with` headers, not a general
      terminator.
- [x] **`parse-fail` rejection** — malformed tokens (unterminated string,
      unterminated block comment, stray `*/`, invalid number) must be a parse
      error, matching the `parse-fail-*` conformance category (doc 15 §3.2).

---

## 2. Strings: literals, escapes, interpolation

### 2.1 Double-quoted strings

- [x] **Basic `"..."`** — byte string (Nix strings are byte strings, not
      validated Unicode; preserve bytes exactly).
- [x] **Escapes** — `\"` (quote), `\\` (backslash), `\n`, `\r`, `\t`, and `\${`
      (literal dollar-brace, suppresses interpolation). `\` before any other
      character yields that character literally. Verify the full escape set
      against pinned Nix.
- [x] **`$${` / dollar runs** — `$$` does not collapse in double-quoted strings.
      An even-length run of dollars before `{` is literal (`$${` stays `$${`,
      `$$$${` stays `$$$${`); an odd-length run leaves the final `${` to open
      interpolation (`$$${` starts interpolation at the third `$`). Verify exact
      `$`-run handling against pinned Nix.
- [x] **Embedded newlines** — a literal newline inside `"..."` is allowed and
      preserved; literal `\r` and `\r\n` normalize to `\n`, matching pinned Nix.

### 2.2 Indented strings (`''...''`)

The indentation algorithm is a frequent source of divergence; reproduce it
exactly.

- [x] **Common-indentation stripping** — strip from each line *a number of spaces
      equal to the minimal indentation of the string as a whole, disregarding the
      indentation of empty lines*. (Verified against the Nix manual string-literals
      page.)
- [x] **Empty/space-only lines excluded from the minimum** — empty lines and
      lines containing only spaces do not lower the computed common indentation.
- [x] **Tabs are NOT stripped** — "prefixed tab characters are not stripped."
      Tabs do not count as the strip unit; a tab-only line is content and can
      lower the common indentation to zero. Mixing tabs and spaces produces the
      well-known surprising output. Reproduce the C++ Nix behavior bug-for-bug
      (see NixOS/nix #3759, #7834), do not "fix" it.
- [x] **Leading newline elision** — "whitespace and newline following the opening
      `''` is ignored if there is no non-whitespace text on the initial line."
      I.e. if the opening `''` is immediately followed by (optional spaces and) a
      newline, that first newline is dropped.
- [x] **Trailing handling** — the final line's content up to the closing `''`
      participates in stripping per the same rule; a trailing newline before a
      space-only closing line is preserved, while the closing indentation is
      dropped, matching pinned Nix.
- [x] **Indented-string escapes** — `''$` escapes a literal `$` (suppresses
      interpolation); `'''` (two single-quotes then a single-quote = `''` literal
      escape) yields a literal `''`; `''\n`, `''\r`, `''\t` yield the control
      chars; `''\` followed by any char yields that char literally. Verify each
      escape against pinned Nix.
- [x] **`$${` in indented strings** — renders literally, same as double-quoted.
- [x] **Interpolation inside `''...''`** — `${e}` works identically to
      double-quoted; the interpolated text is inserted *after* indentation
      stripping is computed on the literal portions. Verify the interaction of
      stripping and interpolation against pinned Nix (the minimum is computed on
      the literal lines, not the interpolated values).

### 2.3 Interpolation / antiquotation (`${...}`)

- [x] **In double-quoted strings** — `"a${e}b"` evaluates `e`, coerces to string
      (§2.4), and concatenates. Contexts union (§3).
- [x] **In indented strings** — as above.
- [x] **In paths** — `./a/${e}` is allowed; **at least one `/` must appear before
      any interpolated expression** for the result to be a path. `./a.${foo}/b`
      is a path; `a.${foo}/b` parses as applying `a.${foo}` to the path `/b`;
      `a.${foo} / b` is division. Verify against pinned Nix
      (string-interpolation page).
- [x] **In attribute names** — `{ ${e} = v; }` and `s.${e}` (dynamic/computed
      attr names, §5.4). The interpolated value must evaluate to a string;
      unlike string/path interpolation, dynamic attr names do not coerce paths
      or attrsets with `outPath` / `__toString`, and context-bearing strings
      are rejected.
- [x] **Only static names in first-position `let` binding names** — a `let`
      binding's first left-hand-side segment must be statically known:
      `let ${"x"} = ...; in ...` is legal and binds `x`, but computed first
      segments such as `let ${e} = ...; in ...` and `let ${"x" + "y"} = ...; in ...`
      are **not** legal. Dynamic attr segments are legal only below a static
      prefix (for example, `let a.${e} = ...; in ...` builds a nested attrset).
      Verify: `let`-binding names are static; reject computed first-segment
      `let` names (**must-error / parse behavior — verify against pinned Nix**).
- [x] **Nested interpolation** — `${"${e}"}` and interpolation inside interpolated
      expressions evaluate recursively.

### 2.4 String coercion (what `${}` and `toString`-style coercion accept)

The set of coercible values is exact; getting it wrong changes both visible
strings and string contexts.

- [x] **String → itself** — identity, context preserved.
- [x] **Path → store path** — a path in an interpolated expression is **copied
      into the Nix store**, and the result is the store path string, *with the
      source path added to the string's context* (§3, §4). This is eval-forces-a
      copy and is observable in `inputSrcs`.
- [x] **Attribute set with `__toString`** — call `__toString self` (a function
      taking the set), use its string result. (Verified: manual string-interpolation.)
- [x] **Attribute set with `outPath`** — coerce via the `outPath` string value
      (this is how derivations interpolate to their out path).
- [x] **`__toString` takes precedence over `outPath`** — "if both `__toString`
      and `outPath` are present, `__toString` takes precedence." Reproduce this
      precedence exactly.
- [x] **Set with neither** — error: "cannot coerce a set to a string"
      (**must-error**).
- [x] **Booleans, null, integers, floats, lists are NOT coercible in interpolation**
      — interpolating them throws. (Note: `builtins.toString` is *more* permissive
      than interpolation for some types — that asymmetry is a doc 21 concern;
      here, pin the *interpolation* coercion set.) Verify the exact coercible set
      for interpolation vs `toString` against pinned Nix.

### 2.5 String concatenation

- [x] **`+` on strings** — `"a" + "b"` concatenates characters *and unions the
      string contexts* (§3). See §6 for the full `+` overload set.

---

## 3. String context (language-level propagation)

String context is the side-band dependency set threaded through string
operations; it is the single highest-risk parity area (see
[compatibility constraints](02-compatibility-constraints.md) §5). The *primops*
that read/write context (`unsafeDiscardStringContext`, `getContext`,
`appendContext`, `storePath`) are specified in
[builtins conformance](21-builtins-conformance.md); the *propagation rules* below
are language-level and live here.

- [x] **Context attaches on coercion of a derivation** — interpolating/`toString`-ing
      a derivation attaches its `=drv`/output context element.
- [x] **Context attaches on path coercion** — coercing a path to a string adds the
      NAR-hashed source store path to the context (and is observed as an `inputSrc`).
- [x] **Context attaches via `builtins.storePath`** — adds the path as a context
      element (builtin in doc 21; the propagation rule is here).
- [x] **Concatenation unions context** — `a + b` carries `context(a) ∪ context(b)`.
- [x] **Interpolation unions context** — `"${a}${b}"` carries the union of every
      interpolated part's context.
- [x] **`//`, comparisons, and other ops do not fabricate context** — only
      string-producing operations propagate; comparisons return bools with no
      context.
- [x] **Context survives string-slicing/replacement** — `substring`,
      `replaceStrings` preserve (do not silently drop) context (the canonical
      divergence; see
      [compatibility constraints](02-compatibility-constraints.md) §5.3). Exact
      per-builtin rules are in doc 21; the invariant — *don't drop context across
      an op Nix preserves it across* — is enforced here.
- [x] **Context is observed by `derivationStrict`** — the union of all string
      contexts handed to `derivationStrict` becomes `inputDrvs`/`inputSrcs`. This
      is the only place context becomes a `.drv` byte (doc 11/21).
- [x] **Context-element kinds round-trip** — plain store path, `=drv`
      (output-specific), and `!`/all-outputs/deep elements must each be
      represented and re-emitted exactly (see
      [compatibility constraints](02-compatibility-constraints.md) §5.1). The
      `getContext`/`appendContext` attrset shape is a doc-21 boundary; the
      language must preserve element identity across it.
- [x] **`unsafeDiscardStringContext` clears exactly** — the boundary primop must
      clear *all* context and nothing more (doc 21); the language guarantees no
      other operation silently clears context.

---

## 4. Paths

Path handling is subtle because of the `/`-disambiguation, home expansion,
search paths, and store coercion.

- [x] **Relative path literal** — `./foo`, `../bar`, `foo/bar` (must contain at
      least one `/` to be recognized as a path). Resolved relative to the
      *directory of the file being evaluated* (the base directory), producing an
      absolute path value.
- [x] **`./.` and `./` forms** — `./.` is the current directory; verify `./`
      acceptance against pinned Nix.
- [x] **Absolute path literal** — `/etc/foo`. A leading `/` makes it absolute.
- [x] **Home-relative path** — `~/foo` expands using the configured home
      directory outside pure evaluation mode. Pure evaluation rejects home paths;
      AOS requires callers to configure the home directory explicitly rather
      than reading the ambient process `HOME`.
- [x] **Path interpolation** — `./a/${e}` (see §2.3): at least one `/` before any
      `${}` for path recognition. Relative interpolated paths resolve against
      the configured path-literal base and remain path values.
- [x] **`/` division-vs-path disambiguation** — `a / b` and `a/ b` are
      division; `a/b` is a path; `a /b` is application to the absolute path
      `/b`. A slash contributes to a path token only when immediately followed
      by a path segment or interpolation.
- [x] **path + path** — `+` on two paths yields a path (§6).
- [x] **path + string** — yields a **path**; the string must not carry store-path
      context. Verify against pinned Nix (manual: "Path + String → path").
- [x] **string + path** — yields a **string**; the path's file/dir **must exist**
      and is **copied into the store** (adds source path + context). Verify the
      existence requirement and the copy/coercion asymmetry vs `path + string`
      against pinned Nix — this asymmetry is a classic foot-gun.
- [x] **Path → store coercion** — store-sensitive coercion boundaries such as
      interpolation, JSON rendering, and derivation attributes copy the
      referenced file/tree into the store (NAR-hashed), yield its store path, and
      attach source-path context observable by derivations as `inputSrcs`. Plain
      `builtins.toString path` remains the raw context-free path string.
- [x] **Search paths `<name>`** — `<nixpkgs>` and `<name/sub>` resolve through
      the explicitly configured search path to a path value. AOS does not read
      ambient `NIX_PATH`; callers provide entries that are reflected by
      `builtins.nixPath`, consumed by `<...>`, and shared with
      `builtins.findFile` in configured order. The runner also models C++ Nix's
      hidden `<nix/...>` corepkgs lookup without reflecting it in
      `builtins.nixPath`, and lexical `__nixPath` overrides for angle-bracket
      imports.
- [x] **Trailing-slash normalization** — path literals ending in a bare slash
      after a valid segment (`foo/bar/`, `./foo/`, `/tmp/`, or interpolated
      `./a/${x}/`) are parser errors matching pinned Nix. `.` and `..`
      components inside path literals normalize against the configured path
      base (`foo/./bar` => `foo/bar`, `foo/../bar` => `bar`).

---

## 5. Attribute sets

### 5.1 Literals and selection

- [x] **Literal `{ a = 1; b = 2; }`** — unordered source, but observable
      traversal is **symbol-collation order**. AOS flat attrsets store a
      raw-byte lexicographic iteration permutation used by `builtins.attrNames`
      and `builtins.attrValues`; source-order data remains separate for
      construction-sensitive internals.
- [x] **Selection `s.a`** — selects attribute `a` from an attrset; the selected
      value is forced by the surrounding demand. Missing attrs are must-errors,
      and non-attr receivers are type errors.
- [x] **Attr-path selection `s.a.b.c`** — dotted path selection descends one
      component at a time through attrsets. A missing leaf or intermediate
      component is a must-error without an `or` default.
- [x] **Selection with `or` default `s.a.b or d`** — `or` supplies a default if
      *any* component of the attr path is missing. The parser attaches the
      default to the whole preceding attr-path selection, and tree-walk tests
      cover missing leaf, missing intermediate, missing first component, and
      non-attr intermediate fallback. `d` stays lazy when the full path exists
      and is forced only when fallback is taken.
- [x] **Dynamic select `s.${e}`** — computed attribute name on selection; `e`
      must evaluate to a string. AOS evaluates dynamic key expressions in path
      order, supports computed string names, and rejects `null`, paths, and
      attrsets with string-coercion hooks and context-bearing strings like
      pinned Nix.
- [x] **`or` with dynamic select** — `s.${e} or d` is legal and follows pinned
      Nix selection-default order: the default remains lazy on success, covers
      missing and non-attr prefixes, does not mask errors from the currently
      reached dynamic key, and skips later dynamic keys after an earlier
      fallback.

### 5.2 Has-attribute `?`

- [x] **`s ? a`** — true iff `s` has attribute `a`. AOS matches pinned Nix:
      the receiver is forced, non-attr receivers return `false`, and present
      or absent leaf values are not forced.
- [x] **Attr-path `s ? a.b.c`** — true iff the full path exists. AOS
      short-circuits to `false` on missing components and, after evaluating the
      reached segment name, non-attr prefixes. It does not force leaf values,
      and only forces existing intermediate values that must be descended
      through.
- [x] **Dynamic `s ? ${e}`** — computed-name has-attr. AOS supports computed
      string names, skips later dynamic keys after an earlier missing prefix,
      and rejects invalid dynamic names (`null`, paths, attrsets, and
      context-bearing strings) like pinned Nix.
- [x] **Precedence** — `?` is precedence 4 (§6); `s ? a && b` parses as
      `(s ? a) && b`.

### 5.3 Nested definitions, merging, duplicate keys

- [x] **Nested attr definition `a.b.c = v;`** — desugars to nested sets
      `a = { b = { c = v; }; };`.
- [x] **Merging of distinct nested paths** — `{ a.b = 1; a.c = 2; }` merges into
      `{ a = { b = 1; c = 2; }; }`. This merge is a parser-level construction,
      not the `//` operator. AOS also matches pinned Nix for literal attrset
      merges in both orders, e.g. `{ a = { b = 1; }; a.c = 2; }`.
- [x] **Duplicate key is an error** — `{ a = 1; a = 2; }` and conflicting nested
      definitions (`{ a.b = 1; a.b = 2; }`) are a **must-error**. AOS rejects
      direct duplicates, scalar-vs-nested conflicts, and literal nested attrset
      leaf conflicts in either order.
- [x] **`inherit x y;`** — copies `x`, `y` from the surrounding lexical scope:
      `inherit x;` ≡ `x = x;`. AOS matches pinned Nix for multiple bare
      inherited names, lexical capture, and lazy inherited values.
- [x] **`inherit (e) x y;`** — copies from set `e`: ≡ `x = e.x; y = e.y;`. `e` is
      evaluated once. AOS matches pinned Nix for multiple inherited fields,
      lazy source evaluation, and one shared source evaluation when multiple
      inherited values are forced.
- [x] **`inherit` in `let`** — `let inherit (e) x; in ...` is legal; same desugar.
      AOS matches pinned Nix for bare let inherit lexical capture, source-based
      let inherit, let self-frame lookup from `inherit (e)`, unused inherited
      bindings staying lazy, duplicate binding rejection, and shared source
      evaluation when multiple inherited let bindings are forced.

### 5.4 `rec` and dynamic attributes

- [x] **`rec { ... }`** — attributes are added to the *lexical scope* of the
      set's own values, enabling self-reference (`rec { a = 1; b = a + 1; }`).
      AOS matches pinned Nix for static self-reference and lazy cyclic members.
- [x] **Non-`rec` sets do not self-scope** — in a plain set, an attr value cannot
      refer to a sibling by bare name. AOS resolves such names to the surrounding
      lexical scope like pinned Nix.
- [x] **Dynamic/computed attrs are NOT recursive targets** — in
      `rec { ${e} = v; a = ...; }`, the dynamically-named attribute is **not**
      visible in the `rec` lexical scope. Pinned Nix does evaluate dynamic name
      expressions and dynamic values in the rec scope for static siblings; AOS
      matches that behavior while excluding computed targets from the frame.
- [x] **Mixing static + dynamic in `rec`** — AOS matches pinned Nix visibility:
      static attrs are visible to each other, dynamic name expressions, and
      dynamic values; dynamic targets are excluded from recursive lexical lookup.
- [x] **`rec` + `inherit`** — `rec { inherit x; y = x; }` brings `x` into the
      recursive scope. AOS matches pinned Nix for inherited source capture from
      the surrounding scope and lazy inherited values.
- [x] **Self-reference laziness** — `rec { a = b; b = a; }` only loops if forced
      (§10 black-holing). AOS matches pinned Nix for unforced cyclic members and
      reports infinite recursion when the cycle is forced.
- [x] **Plain vs quoted dynamic keys under `null`** — the two dynamic-key
      forms differ: a plain `${e}` binding whose name evaluates to `null` is
      **silently skipped** (`{ ${null} = 1; }` is `{ }`; nested paths keep
      the static prefix: `{ a.${null} = 1; }` is `{ a = { }; }` — this is the
      `${if cond then "x" else null}` idiom), while a quoted `"${e}"` key is
      a string interpolation that always coerces its fragments, so
      `{ "${null}" = 1; }` is a **must-error** ("cannot coerce null to a
      string"), as are `"a${null}"` and the plain-wrapping-a-string form
      `${"${null}"}`. The quoted form is also always a *dynamic* attribute
      even over a string literal: `let "${"b"}" = 1; in b` and
      `inherit (x) "${"a"}";` are must-errors (dynamic attrs not allowed in
      `let`/`inherit`), and `rec { "${"a"}" = 1; b = a; }` does not put `a`
      in scope. AOS matches pinned Nix on all forms (the parser wraps a
      quoted key that collapses to a single interpolation in a second
      `Interp` layer so it never degrades to the plain skip-on-null form).

---

## 6. Operators: precedence, associativity, overloads

The precedence/associativity table below is reproduced from the Nix manual
operators page and **must** be matched exactly (a precedence error silently
re-associates an expression and changes its value). Precedence 1 binds tightest.

| Prec | Operator | Form | Name | Assoc |
|---|---|---|---|---|
| 1 | `.` | `e . attrpath [or e]` | Attribute selection | none |
| 2 | (juxtaposition) | `f e` | Function application | left |
| 3 | `-` | `- e` | Arithmetic negation | none |
| 4 | `?` | `e ? attrpath` | Has attribute | none |
| 5 | `++` | `e ++ e` | List concatenation | **right** |
| 6 | `*` `/` | `e * e`, `e / e` | Multiplication / Division | left |
| 7 | `+` `-` | `e + e`, `e - e` | Addition / Subtraction (and string/path `+`) | left |
| 8 | `!` | `! e` | Logical NOT | none |
| 9 | `//` | `e // e` | Update | **right** |
| 10 | `<` `<=` `>` `>=` | `e < e` … | Comparison | none |
| 11 | `==` `!=` | `e == e` | Equality / Inequality | none |
| 12 | `&&` | `e && e` | Logical AND | left |
| 13 | `\|\|` | `e \|\| e` | Logical OR | left |
| 14 | `->` | `e -> e` | Logical implication | **right** |
| 15 | `\|>` `<\|` | `e \|> f`, `f <\| e` | Pipe (experimental) | left / right |

- [x] **`.` selection — precedence 1, non-associative** — binds tighter than
      application; `f x.y` is `f (x.y)`.
- [x] **Function application — precedence 2, left** — `f a b` ≡ `((f a) b)`
      (currying, §8).
- [x] **Unary `-` negation — precedence 3, prefix** — applies to a number. Pinned
      Nix accepts chained prefix negation (`let x = 1; in - -x`); AOS parses it
      as nested negation.
- [x] **`?` has-attr — precedence 4, non-associative** (§5.2).
- [x] **`++` list concat — precedence 5, RIGHT-associative** — `a ++ b ++ c` ≡
      `a ++ (b ++ c)`.
- [x] **`*` `/` — precedence 6, left** — numeric multiply/divide. `/` here is
      division (the path `/` is a *lexical* distinction, not this operator; §4).
- [x] **`+` `-` — precedence 7, left** — numeric add/subtract.
- [x] **`!` logical NOT — precedence 8, prefix** — AOS matches pinned Nix:
      `! a == b` parses as `(!a) == b`; `!` is looser than arithmetic but tighter
      than equality.
- [x] **`//` update — precedence 9, RIGHT-associative** — `a // b // c` ≡
      `a // (b // c)`. Right-assoc + right-bias means `c`'s keys win.
- [x] **Comparison `< <= > >=` — precedence 10, non-associative** — `a < b < c` is
      a parse error.
- [x] **Equality `== !=` — precedence 11, non-associative** (§7).
- [x] **`&&` — precedence 12, left, short-circuits** — RHS not forced if LHS is
      `false`.
- [x] **`||` — precedence 13, left, short-circuits** — RHS not forced if LHS is
      `true`.
- [x] **`->` implication — precedence 14, RIGHT-associative** — `a -> b` ≡
      `!a || b`; short-circuits (RHS not forced if LHS is `false`). `a -> b -> c`
      ≡ `a -> (b -> c)`.
- [x] **Pipe `|>` / `<|` — precedence 15 (experimental)** — local C++ Nix
      2.24.5 reports `pipe-operators` disabled by default; aos-nix rejects
      `|>`/`<|` by default and does not implement a pipe feature gate because
      AOS does not use the experimental syntax.

### 6.1 `+` operator overloads (precedence 7)

- [x] **int + int → int** — i64 arithmetic (§7).
- [x] **float + float → float**, and **int + float / float + int → float**
      (promotion, §7).
- [x] **string + string → string** — concatenation + context union (§2.5, §3).
- [x] **path + path → path**.
- [x] **path + string → path** (string must lack store-path context; §4).
- [x] **string + path → string** (path must exist, copied to store; §4).
- [x] **Mismatched `+` operands error** — e.g. `int + string`, `bool + bool`,
      `list + list` (lists use `++`, not `+`) are **must-error**. Verify the full
      legal/illegal `+` matrix against pinned Nix.

### 6.2 `//` update operator (precedence 9)

- [x] **Shallow right-biased merge** — result has all attrs of both; on key
      collision the **right** operand's value wins. **Shallow**: nested sets are
      *replaced*, not deep-merged (`{a={x=1;};} // {a={y=2;};}` → `{a={y=2;};}`).
      Verify the shallow (non-recursive) semantics against pinned Nix.
- [x] **Strict to WHNF in both args** — both operands forced to WHNF (to enumerate
      keys); attr *values* are not forced. Verify.

### 6.3 `++` list concatenation (precedence 5)

- [x] **`a ++ b`** — concatenates lists; element thunks are shared (not forced).
- [x] **Non-list operand errors** (**must-error**).

---

## 7. Numbers, arithmetic, equality, comparison

### 7.1 Integer and float arithmetic

- [x] **Integers are i64** — 64-bit signed.
- [x] **i64 overflow behavior** — reproduce C++ Nix's exact overflow semantics.
      C++ Nix performs signed 64-bit arithmetic. **Modern Nix (≥ 2.25, via
      NixOS/nix#11188, merged Aug 2024) *throws* on signed-64-bit overflow rather
      than wrapping** — `add`/`sub`/`mul` that would overflow raise an evaluation
      error, and negating `i64::MIN` also throws. Older Nix wrapped
      (two's-complement, undefined behavior). Which behavior applies is therefore
      **version-dependent and observable** — **verify against pinned Nix**: if the
      pinned rev is ≥ 2.25 reproduce the throw-on-overflow (catchable) error; if
      older, reproduce wrapping. Pin the exact error class.
- [x] **Float arithmetic** — IEEE-754 double; reproduce rounding exactly.
- [x] **int/float mixing & promotion** — any binary arithmetic with one float
      operand promotes to float; int+int stays int. Verify promotion for `+ - * /`.
- [x] **Division** — `int / int`: verify whether it is integer (truncating) or
      float division in the pinned Nix (Nix `int / int` yields an **int** via
      truncation; `/` with a float operand yields a float). **Verify** the
      truncation/rounding direction (toward zero?) against pinned Nix.
- [x] **Division by zero** — `x / 0` is a **must-error**; verify the error class.
- [x] **Unary negation** — `-x` for int and float (§6 precedence 3).

### 7.2 Printing/formatting of numbers (observable!)

- [x] **Integer printing** — raw numeric rendering and `toString` must format
      integers exactly as C++ Nix does (no thousands separators, leading `-` for
      negatives).
- [x] **Float printing** — reproduce C++ Nix's **exact** float-to-string
      formatting (precision, trailing zeros, exponent form). This is a notorious
      divergence source (the conformance `eval-okay-*` cases compare rendered
      values byte-for-byte; doc 15 §3.2). **Verify the exact float format**
      (significant digits, `%g`-style?) against pinned Nix.
- [x] **`toString` of int vs float** differs in formatting; pin both.

      Note: the raw-rendering check here is number-scoped. It pins the numeric
      byte format that C++ Nix exposes through `--eval`; full raw rendering for
      non-number values is covered by the later value-rendering/corpus harness.

### 7.3 Equality `==` / `!=`

- [x] **Deep structural equality** — `==` compares by value, recursively.
- [x] **Partial strictness** — "evaluated until a difference is found" — `==`
      forces both sides only as far as needed to decide; reproduce the
      short-circuit forcing so that *un-demanded* errors don't fire (e.g.
      `[1 (throw "x")] == [2 (throw "y")]` should be `false` without forcing the
      throwing elements). **Verify the exact forcing order against pinned Nix.**
- [x] **Attribute sets** — equal iff same key set and all values equal
      (after key-set comparison, values are forced/compared in pinned C++ Nix's
      symbol order, not source order).
- [x] **Lists** — equal iff same length and elementwise-equal.
- [x] **int vs float cross-equality** — `1 == 1.0` is **`true`**: Nix treats the
      two numeric types as type-compatible for `==` (the operators page states
      numbers are compared as type-compatible). Reproduce int/float cross-equality
      as `true` for equal numeric values; pin the precision corner (below) against
      pinned Nix.
- [x] **Functions compare unequal *by structural equality*** — a *direct*
      comparison of two functions returns `false`, including a function with
      itself: `let f = x: x; in f == f` is **`false`** (each lambda has a fresh
      identity; structural function equality is undefined and returns `false`).
      **But there is a pointer-equality wart (NixOS/nix#3371): when the *same*
      function value is nested inside two containers compared structurally**
      (e.g. `let f = x: x; in [ f ] == [ f ]`), C++ Nix may short-circuit via
      *pointer/value identity* and return `true` — i.e. function equality is
      `false` at top level but a shared function thunk inside compared
      lists/attrsets can compare equal by identity. Reproduce this exact
      asymmetry bug-for-bug; do not "fix" it. **Verify the precise
      pointer-equality short-circuit points against pinned Nix.**
- [x] **Derivations / sets with `outPath`** — plain sets that merely contain
      `outPath` compare structurally, while `type = "derivation"` wrappers use
      the forced `outPath` value for equality and ignore wrapper-only attrs.
      This is pinned by `eval-okay-eq-derivations` and local malformed-wrapper
      regression tests.
- [x] **Float precision corner** — "floating-point precision is limited"; equal
      floats that differ in low bits compare unequal. Reproduce IEEE semantics.
- [x] **NaN** — if a NaN is reachable (e.g. via builtins producing it), `NaN ==
      NaN` is false and ordering is undefined; verify reachability and behavior
      against pinned Nix (pinned Nix 2.24.12 reaches NaN via overflow arithmetic,
      compares direct `NaN == NaN` as false, and returns false for `NaN < NaN`).

### 7.4 Comparison `< <= > >=`

- [x] **Numbers** — numeric ordering; int/float cross-compare promotes (verify).
- [x] **Strings** — byte-lexicographic ordering. Verify it is byte-wise (not
      locale/collation) against pinned Nix.
- [x] **Paths** — byte-lexicographic ordering on path bytes; pinned Nix 2.24.12
      supports both operator comparison and `builtins.lessThan` on paths.
- [x] **Lists** — lexicographic, elementwise: compare element 0, then 1, …; a
      shorter prefix list is less. **Verify** Nix supports list `<` and its exact
      semantics against pinned Nix (some versions restrict comparable types).
- [x] **Type restrictions** — comparison is defined only on numbers, strings,
      paths, and (per above) lists; comparing other types (bools, sets, null,
      functions) is a **must-error**. Verify the exact comparable-type set.
- [x] **Mixed-type comparison errors** — e.g. `1 < "a"` is a **must-error**
      (verify; numbers cross-compare but number-vs-string does not).
- [x] **Non-associative** — `a < b < c` is a parse error (§6).

---

## 8. Functions

- [x] **Single-param lambda `x: body`** — `x` binds the argument in `body`.
- [x] **Currying** — `x: y: body` is a one-arg function returning a one-arg
      function; application is left-associative (§6).
- [x] **Attrset pattern `{ a, b }: body`** — destructures an attrset argument;
      requires exactly `a` and `b` present; present values remain lazy until
      demanded.
- [x] **Missing required attr errors** — calling `{ a, b }: …` with `{ a = 1; }`
      is a **must-error**; pinned Nix reports `function 'anonymous lambda' called
      without required argument 'b'`.
- [x] **Extra attr without `...` errors** — calling `{ a }: …` with
      `{ a = 1; b = 2; }` is a **must-error**; pinned Nix reports
      `function 'anonymous lambda' called with unexpected argument 'b'`.
- [x] **Defaults `{ a ? d }: body`** — `d` is used if `a` is absent; default
      expressions may reference earlier formals, later formals, and an
      `@`-binding for the original argument attrset.
- [x] **Default laziness** — `d` is only evaluated when the attr is absent and
      the formal's value is demanded (§10).
- [x] **Ellipsis `{ a, ... }: body`** — allows and ignores extra attributes;
      ignored values remain lazy.
- [x] **`@`-pattern, name on left: `args@{ a, ... }: body`** — `args` binds the
      whole passed attrset.
- [x] **`@`-pattern, name on right: `{ a, ... } @ args: body`** — equivalent
      form; both are accepted.
- [x] **`@`-pattern alias collisions** — `args@{ args, ... }: body` and
      `{ args, ... } @ args: body` are parse errors; the alias is a binding and
      cannot duplicate a formal name.
- [x] **`args@` excludes defaults** — "`args` does *not* include any default
      values specified with `?`" — `args` is the attrset *as passed*, before
      defaults are filled.
- [x] **Pattern + `@` strictness** — without `...`, an `@`-pattern still rejects
      unexpected attrs; the `@`-binding does not relax the closed-set check.
- [x] **Argument is forced to WHNF for pattern match** — matching `{ a, b }:`
      forces the argument to an attrset (WHNF) to enumerate keys; values stay
      lazy.
- [x] **Direct function equality is false** (cross-ref §7.3) — a function value
      compares unequal to everything under *direct* `==`, including itself; note
      the nested pointer-equality wart in §7.3 (a shared function inside compared
      containers can compare equal by identity).
- [x] **Functions are not coercible to string** (cross-ref §2.4) —
      interpolating a function is a **must-error**.

---

## 9. Recursion and fixed points

- [x] **`rec` self-reference** — `rec { a = 1; b = a + 1; }` (§5.4).
      Verified against pinned Nix for direct and forward self-scope.
- [x] **`let` self/forward reference** — `let a = b; b = 1; in a` (order-independent
      within a `let`). Verified chained forward references.
- [x] **`fix` / Y-combinator idiom** — `let fix = f: let x = f x; in x;` (the
      nixpkgs `lib.fix`) must evaluate correctly under laziness; `fix (self: { … })`
      is the nixpkgs overlay/fixpoint pattern. This is a *consequence* of laziness,
      not a builtin — it must "just work" once thunks + `let` recursion are right.
- [x] **Mutual recursion** — `rec { a = b; b = a; }` (cyclic, only diverges if
      forced) and `let even = n: …odd…; odd = n: …even…; in …` must work.
      Verified lazy cyclic attrs plus mutually recursive functions.
- [x] **Cyclic data via laziness** — a thunk may reference a binding that
      references it back; as long as forcing terminates, it is valid (e.g. infinite
      lists consumed by `take`). Verify lazy cyclic structures evaluate.
      Verified self-referential attrs and lists consumed through finite selects.
- [x] **Fixpoint over attrsets** — `genericClosure`-style and `fix`-style
      fixpoints (the *builtin* `genericClosure` is doc 21; the *language*
      requirement is that recursive `let`/`rec` + laziness make fixpoints
      expressible). Verified `fix (self: { package = ... self.package ...; })`.
- [x] **Infinite recursion detection (black-holing)** — forcing a thunk that is
      already under evaluation must raise "infinite recursion encountered"
      (**must-error**), not hang or stack-overflow silently. Reproduce the
      black-hole/blackhole mechanism and its error class. Verify the exact
      trigger conditions against pinned Nix.
      Verified `let` and `rec` self/mutual cycles against pinned Nix's final error.
- [x] **Stack-depth / recursion limit** — verify whether the pinned Nix imposes a
      max-call-depth and whether AOS expressions hit it; match the error class if
      so. Pinned Nix config/source defaults `max-call-depth = 10000`; AOS exposes
      the same default and matches configured `--option max-call-depth` boundary
      successes and failures in the oracle suite. Every tree-walk node enters
      through a segmented-stack guard (256 KiB red zone, 2 MiB segments), so
      recursion reaches that semantic limit instead of exhausting the native
      thread stack. A 512 KiB-thread regression proves a terminating depth-1500
      function succeeds and an unbounded function returns the exact default
      depth error at call 10001 while unwinding the evaluator's depth counter.

---

## 10. Laziness and evaluation

- [x] **Call-by-need / WHNF** — expressions evaluate to *weak head normal form*
      on demand; sub-structures stay thunked until forced. This is the core
      evaluation model. Verified attr/list/lambda WHNF boundaries against pinned
      Nix.
- [x] **Thunks** — every unforced binding/argument/list-element/attr-value is a
      thunk; successful forces are memoized, while failed forces reset and may be
      retried. Verified shared let bindings, lambda arguments, list elements, and
      attr values trace once after successful repeated forcing; verified failed
      throwing thunks trace again on retry like pinned Nix.
- [x] **Un-demanded errors do not fire** — `let x = throw "e"; in 1` evaluates to
      `1`; `{ a = throw "e"; b = 2; }.b` evaluates to `2`. This is the
      admissibility boundary for any strictness analysis (see
      [laziness analyses](07-laziness-and-whole-program-analyses.md) and
      [compatibility constraints](02-compatibility-constraints.md) §6): forcing a
      thunk Nix would not force can turn a non-error into an error — observable,
      therefore forbidden. Verified latent `throw` and `abort` cases in
      let/lambda/list/attr positions.
- [x] **`seq` (shallow force)** — `builtins.seq a b` forces `a` to WHNF then
      returns `b` (builtin in doc 21; the *evaluation effect* — forcing to WHNF
      only, not deep — is the language behavior to match). Verified shallow
      forcing and left-to-right errors against pinned Nix.
- [x] **`deepSeq` (deep force)** — forces `a` fully (recursively) then returns
      `b`; reproduce the deep-forcing order and that it makes otherwise-hidden
      errors fire (e.g. `deepSeq { x = throw "e"; } 1` throws). Builtin in doc 21.
      Verified nested list/attr forcing, cyclic data, attr source order, and
      delayed second-argument forcing.
- [x] **`tryEval` catches `throw` and `assert`** — `(tryEval (throw "x")).success`
      is `false`; same for a failed `assert`. (Verified: tryEval catches throw and
      assert.)
- [x] **`tryEval` does NOT catch `abort`** — `abort` is uncatchable by design;
      `tryEval (abort "x")` aborts the whole evaluation. Reproduce this
      non-catchability. (Verified.)
- [x] **`tryEval` does NOT deep-force** — `(tryEval { x = throw "e"; }).success`
      is `true` because `tryEval` only forces to WHNF; the inner `throw` is never
      demanded. Reproduce the shallow-force semantics exactly. (Verified.)
- [x] **`tryEval` and non-catchable evaluator errors** — builtin type errors,
      missing attributes, and list-bounds failures are not converted by
      `tryEval`; they remain ordinary evaluation failures.
- [x] **Evaluation order of errors is observable in some contexts** — which of two
      failing branches surfaces first can depend on forcing order; reproduce
      Nix's order where observable (see
      [parallel evaluation](13-parallel-evaluation.md) for the parallel caveat).
      Verified `seq`, `deepSeq`, and strict-builtin throw ordering against pinned
      Nix.

---

## 11. `let`, `with`, and scoping

### 11.1 `let ... in`

- [x] **`let a = 1; b = a + 1; in body`** — bindings are mutually recursive and
      order-independent; visible in later bindings and in `body`. Verified direct,
      nested, lazy, and forward references against pinned Nix.
- [x] **`let` with `inherit`** — `let inherit (e) x; in …` (§5.3). Verified
      lexical inherit, sourced inherit, forward source references, missing-source
      laziness, and shared source forcing against pinned Nix.
- [x] **`let` binding names are static** — no dynamic/computed names (§2.3).
      Verified static literal interpolations and rejection of computed keys
      (`let name = "a"; ${name} = ...`) against pinned Nix.
- [x] **Duplicate `let` binding errors** — `let a = 1; a = 2; in …` is a
      **must-error**. Verified direct and inherit-introduced duplicates against
      pinned Nix.

### 11.2 The deprecated `let { ... }` body form

- [x] **`let { x = …; body = …; }`** — the legacy recursive form whose value is
      its `body` attribute (`let { body = "x"; }` ≡ `"x"`). **Decision: support
      it for pinned-Nix parity despite deprecation.** The parser desugars the
      binding block to a recursive attrset selected at `.body`, so the normal
      recursive-attrset resolver/lowerer/evaluator path handles self-reference,
      quoted `"body"` attributes, dotted `body.*` bindings, and dynamic body
      keys such as `${name}`. The former `legacy let-attrset syntax gap`
      conformance exclusions have been removed.

### 11.3 `with`

- [x] **`with e; body`** — introduces the attributes of set `e` into the *dynamic*
      scope of `body` (their names become usable as bare identifiers). Verified
      lookup, function values, non-attr/missing-name failures, unshadowable
      top-level names (`true`, `builtins`, `map`, `toString`, first-class
      `derivationStrict`), and shadowable builtin attrs (`currentTime`,
      `storeDir`, `length`, `concatMap`) against pinned Nix.
- [x] **`with` binds LOOSER than lexical scope** — *the bindings introduced by
      `with` do not shadow bindings introduced by other means* (a `let`/lambda/`rec`
      binding of the same name **wins** over a `with`). Concretely
      `let a = 3; in with { a = 1; }; a` is `3`, equivalent to
      `let a = 1; in let a = 3; in a`. Reproduce this precedence exactly — it is
      the opposite of most languages' intuition. Verified against pinned Nix.
- [x] **Inner `with` shadows outer `with`** — `with a; with b; x` resolves `x`
      from `b` first, then `a`. Verify the innermost-wins order among nested
      `with`s. Verified against pinned Nix.
- [x] **`with` does not capture statically-unknown names for error reporting** —
      an undefined bare identifier under `with` is resolved at *use* time; verify
      the error behavior (undefined variable) when no `with` set provides it.
      Verified missing-name and non-attr forcing failures against pinned Nix.
- [x] **`with` is lazy in `e`** — `e` is forced to WHNF only when a name resolved
      through it is actually used. Verify the forcing point. Verified unused
      throwing scopes/attrs remain latent and used traced scopes force once.
- [x] **Interaction with lambda params** — a function parameter shadows a `with`
      binding of the same name (lexical wins). Verified against pinned Nix.

---

## 12. Control flow and errors

- [x] **`if c then a else b`** — `c` forced to a bool (**must-error** if not a
      bool); only the taken branch is forced (§10). Both `then` and `else` are
      mandatory (no `if` without `else`). Verified branch choice, bool condition
      errors, untaken-branch laziness, and missing-`else` parse rejection against
      pinned Nix.
- [x] **`assert c; body`** — if `c` is `false`, **must-error** (assertion
      failed); else evaluates `body`. `c` forced to bool. Catchable by `tryEval`
      (§10). Verified success, false assertion failure, condition type errors,
      body laziness, and `tryEval` catchability against pinned Nix.
- [x] **`builtins.throw msg`** — raises a catchable error with `msg`
      (builtin in doc 21; language behavior: catchable by `tryEval`, forced only
      when demanded).
- [x] **`builtins.abort msg`** — raises an **uncatchable** error; `tryEval` does
      not catch it (§10). Builtin in doc 21.
- [x] **`throw` vs `abort` vs `assert` — catchability matrix**:
      `throw` catchable, `assert` catchable, `abort` **not** catchable. Reproduce
      this matrix exactly (it gates the `EvalError`-vs-fatal distinction the
      integration relies on; see
      [integration with AOS](14-integration-with-aos.md)).
- [x] **Error *class* parity** — type errors stay type errors, throws stay
      throws, assertion failures stay assertion failures (doc 15 §3.3). Error
      *text* parity is best-effort (doc 15 §3.3, doc 02 §8 Q4). Verified local
      `TreeWalkErrorKind` classes for type, throw, abort, and assertion failures,
      plus pinned Nix catch/reject behavior for the same cases.
- [x] **Errors are values-in-flight, not exceptions to user code** — except where
      `tryEval` converts them; an un-demanded error stays latent (§10). Verified
      latent errors in unused bindings, attrs, lists, and untaken branches, plus
      shallow `tryEval` values, against pinned Nix.

---

## 13. Imports and scoping across files

- [x] **`import path`** — parse and evaluate the file at `path`, returning its
      value. The imported expression is evaluated in a *fresh* scope (it does not
      see the importer's `with`/`let` — `import` is not textual inclusion).
      Verify the scope isolation against pinned Nix.
- [x] **Import a directory** — `import ./dir` loads `./dir/default.nix`. Verify
      the `default.nix` resolution and the error when it is absent (**must-error**).
- [x] **Import caching** — a given store path / file is parsed+evaluated **once**
      and the result is shared across all `import`s of it (memoized by resolved
      path). Reproduce the caching so repeated imports share thunks (observable
      via identity and via single-evaluation of top-level effects). Verify the
      cache key (canonicalized path?) against pinned Nix.
- [x] **`import` forces the path argument** — coerces its argument to a path/store
      path before reading the imported source. Importing a derivation output is
      covered by the IFD row below.
- [x] **`scopedImport`** — variant that injects extra bindings into the imported
      file's global scope (builtin in doc 21; the language-level note is that it
      changes the *scope* the imported file evaluates in, unlike plain `import`).
      Verified injected globals, builtin/import shadowing, escaped values, plain
      import freshness, and deliberate non-memoization against pinned Nix.
- [x] **Import-from-derivation (IFD)** — importing/reading a path that is a
      *derivation output* forces that derivation to be **built** before evaluation
      can continue. aos-nix detects derivation-output string contexts at the
      shared filesystem/source-path coercion boundary, materializes known native
      `.drv` closures before the build handoff, and invokes an `IfdRealizer`
      callback before retrying the filesystem read. `aos-core` wires native
      evaluators to a `NixCli::realise`-backed realizer for the current eval
      config; missing/failed realizers remain explicit fallback-eligible errors.
      Focused tree-walk/native tests cover no-realizer errors, restricted-mode
      denial before realization, mixed opaque/derivation context rejection,
      realization before `readFile`, `readDir`, `pathExists`, `readFileType`,
      `builtins.path` source coercion, and `import`, plus native instantiation
      materializing known `.drv` closures before calling the realizer. The full
      transitive `.drv`/output-path byte gate remains tracked in docs 11 and 15.

---

## 14. The `__`-attributes observed by the language/coercion layer

These magic attributes are interpreted by the *evaluator core* (not just the
derivation layer). Distinguish language-level (coercion/application) from
derivation-level (consumed by `derivationStrict`).

- [x] **`__functor` (language-level)** — *a set with a `__functor` attribute whose
      value is callable can be applied as if it were a function, with the set
      itself passed in first*: `(s) arg` ≡ `s.__functor s arg`. Reproduce exactly,
      including the recursive case (`__functor` whose value is itself a
      functor-set) and that this is how nixpkgs attaches metadata to callables.
      (Verified against the syntax page.)
- [x] **`__toString` (language-level)** — string-coercion hook for attrsets;
      `__toString self` is called, takes precedence over `outPath` (§2.4).
- [x] **`outPath` (language-level coercion)** — string-coercion fallback when
      `__toString` is absent (§2.4); this is how derivations and flake inputs
      interpolate.
- [x] **`__structuredAttrs` (derivation-level)** — changes how `derivationStrict`
      serializes env/args (doc 11/21); **not** a language-coercion attribute.
      Listed here only to mark it as *not* language-level — the language passes it
      through to the derivation layer unchanged.
- [x] **`__impure` (derivation-level)** — marks an impure derivation
      (doc 11/21); not language-level. Implemented in `derivationStrict` as
      derivation output metadata, with invalid marker combinations rejected and
      ordinary language-level `__impure` attr behavior covered. AOS package code
      currently uses only `__impure = false` for fixed-output `fetchurl`, so true
      impure derivations are compatibility support rather than package-set policy.
- [x] **Other `__`-prefixed derivation attributes** (`__contentAddressed`,
      `__darwinAllowLocalNetworking`, etc.) — pass-through to the derivation layer
      (doc 11/21), not interpreted by the language. Language-layer behavior is
      regression covered for representative derivation-marker names outside
      `derivationStrict`:
      `__contentAddressed`, `__darwinAllowLocalNetworking`, `__ignoreNulls`,
      `__impure`, and `__structuredAttrs` select, inherit, compare, and enumerate
      normally; per-marker derivation-layer semantics remain tracked separately.

---

## 15. Explicitly out of scope

Stated so the design record does not overstate coverage. Each exclusion is a
*deliberate, documented* decision (mirroring the skip-list discipline in doc 15
§3.4), not a silent omission.

- [x] **Deprecated unquoted URL literals** — bare URLs like `http://example.com`
      as string literals (without quotes). These are **deprecated in stock Nix**,
      but aos-nix implements them for compatibility rather than keeping this as a
      skip: the lexer emits `TokenKind::Uri`, the parser/IR preserve URI literal
      nodes, and the tree-walk evaluator returns them as strings. Coverage:
      `syntax::lexer::tests::accepts_and_rejects_uri_scheme_boundaries`,
      `syntax::lexer::tests::uri_fragment_marker_starts_line_comment`,
      `syntax::lexer::tests::distinguishes_paths_division_update_and_uris`,
      `compile::ir::tests::uri_literals_are_trivial_values`, and
      `eval::tree_walk::tests::evaluates_uri_literals_as_strings`. Verified
      against local C++ Nix 2.24.5 with
      `nix-instantiate --eval --json --expr 'http://example.com/a-b?c=d'`;
      raw `#` fragment markers are covered against the same oracle behavior; and
      against AOS sources with `rg` source scans: URL-looking hits are comments,
      strings, or shell/test command text, so the package set does not rely on
      unquoted fetch URLs in expression position.
- [x] **Deprecated `let { ... body = ...; }` form** — covered as *deprecated* in
      §11.2 and implemented for pinned-Nix parity rather than skipped.
- [x] **Experimental pipe operators `|>` / `<|`** — covered conditionally in §6;
      local C++ Nix 2.24.5 reports `pipe-operators` disabled by default, and
      aos-nix rejects both operators by default
      (`syntax::parser::tests::rejects_pipe_operators_without_feature_gate`).
      Verified AOS `.nix` sources do not use pipe operators in expression
      position; the only source hit is a `sed` delimiter inside the glibc
      bootstrap shell script.
- [x] **CA derivations at the language layer — IN SCOPE (not out of scope).**
      Content-addressed derivations are a **required surface from the start** (a
      deliberate design choice for aos-nix; see
      [derivation and store compatibility](11-derivation-and-store-compatibility.md)).
      The language constructs that *produce* them (`__contentAddressed`,
      `outputHashMode = "recursive"`, the CA context-element kinds) and their
      language-observable effects must be correct and are gated, not deferred. Only
      truly *dynamic* derivations (`outputOf` / the experimental
      `dynamic-derivations` feature) remain conditionally scoped — implemented iff
      the pinned Nix enables the feature and the AOS set exercises it. This item is
      listed in §15 only to *correct the record*: CA is no longer an exclusion.
      Language-layer representation is implemented: `derivationStrict` handles
      floating CA and fixed-output precedence, emits placeholders for deferred
      outputs, partitions context into input sources/input derivations, supports
      structured attrs and downstream deferred outputs, and native instantiation
      records floating CA `.drv` bytes. The broader full-closure byte-parity gate
      remains tracked in doc 11/21.
- [x] **Flakes / the flake language layer** — `flake.nix` schema validation,
      `inputs` graph resolution, `outputs` protocol, `flake.lock` semantics,
      registries, and the flake eval cache are out of scope for the evaluator
      core. Verified AOS package/system evaluation uses the non-flake
      `default.nix` / `-A` path; the repository root `flake.nix` has no external
      inputs and derives its outputs from `import ./.`. Native support for
      `parseFlakeRef`, `flakeRefToString`, selected `fetchTree` inputs, and a
      narrow local-inputless `getFlake` path is tracked as builtin coverage in
      doc 21 and does not constitute full flake-layer support.
- [x] **Error-message *text* byte-parity** — explicitly best-effort, not gated
      (doc 02 §8 Q4, doc 15 §3.3). Error *class* parity is in scope (§12).
      Verified as a scope decision: doc 02/15/19/20/24 consistently separate
      hard error-class/catchability parity from soft rendered-diagnostic text
      parity. Package-specific error-text assertions remain enumerated and handled
      per case before those packages use native eval; there is no global
      byte-identical diagnostic-text gate.
- [x] **Non-pure-eval-mode features** — if AOS evaluates in pure mode, `~`-home
      paths (§4), `<...>` search paths via `NIX_PATH` (§4), and other impure
      lookups may be *disabled and must-error*; verify the AOS eval mode and scope
      accordingly.
      Verified scope: AOS exposes explicit Ambient/Impure/Pure/Restricted policies
      instead of being pure-only; native evaluation requires an explicit policy and
      falls back for ambient or unrepresentable `NIX_PATH`. Pure mode hides
      configured home/search-path/environment/current-system/current-time impurity
      and denies unallowed filesystem reads, while explicit impure mode passes the
      configured values through.

---

## 16. Cross-references and ownership

- The **builtins/primops catalog** (`builtins.*`, `derivationStrict`, `import`
  internals, string-context primops, `seq`/`deepSeq`/`tryEval` definitions) is
  [builtins conformance](21-builtins-conformance.md). This document references
  them by name and pins only their *language-observable* effects.
- **Attribute iteration order** (symbol-collation) is owned by
  [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md);
  flagged here (§5.1) as an observable-surface dependency.
- **String-context representation and propagation invariants** are detailed in
  [compatibility constraints](02-compatibility-constraints.md) §5; §3 here is the
  language-level propagation checklist that feeds it.
- **Derivation / ATerm / store-path encoding** (the `.drv` bytes the gate diffs)
  is [derivation and store compatibility](11-derivation-and-store-compatibility.md).
- **The parser and IR** that lexes/parses every §1–§6 construct is
  [frontend parser and IR](04-frontend-parser-and-ir.md); the **value model** for
  §5/§7/§10 is [value representation](05-value-representation.md).
- **Laziness/strictness admissibility** (the boundary that §10 enforces) is
  [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).
- **The conformance corpus** that *enumerates* every item above is
  [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
  §3 (`eval-okay`/`eval-fail`/`parse-okay`/`parse-fail`).

---

## 17. Summary

This checklist enumerates the **language** half of aos-nix's parity obligation:
lexing (§1), strings and the exact indented-string stripping rules (§2), the
side-band string-context propagation that drives the dependency graph (§3), path
literals and the `/`-disambiguation and store-coercion asymmetries (§4),
attribute sets including `rec` and dynamic-name non-recursion (§5), the full
operator precedence/associativity table with the `+`/`//`/`++` overloads (§6),
i64/float arithmetic, number formatting, and structural equality including the
"direct function equality is false" rule and its nested pointer-equality wart (§7), function patterns with the `@`-binding
and default-scoping subtleties (§8), fixed points and black-holing (§9),
call-by-need laziness with the `tryEval`-catches-throw/assert-but-not-abort and
shallow-force rules (§10), `let`/`with` scoping with the *`with` binds looser
than lexical scope* rule (§11), control flow and the throw/abort/assert
catchability matrix (§12), import semantics and IFD (§13), and the language-level
`__functor`/`__toString`/`outPath` magic attributes (§14). Everything not
covered is explicitly scoped out (§15): experimental pipe operators
(feature-gated) and error-text byte-parity (best-effort). Deprecated unquoted
URL literals and the deprecated `let {}` body form are no longer exclusions
because aos-nix implements them for C++ Nix compatibility.
Every `- [ ]` is both a unit of implementation work and a
conformance-suite assertion; items tagged **verify against pinned Nix** are the
ones whose behavior is implementation-defined and must be confirmed against the
exact C++ Nix rev AOS builds against (doc 15 §9 Q1), never inferred from the
manual.

---

## References

External claims were verified against the following sources.

- Nix Reference Manual — Operators (the precedence/associativity table, `+`
  overloads, `//` update, `==` equality semantics):
  <https://nix.dev/manual/nix/2.34/language/operators>
  and the source of truth on master:
  <https://github.com/NixOS/nix/blob/master/doc/manual/source/language/operators.md>
- Nix Reference Manual — Syntax and semantics (`with`/`let`/`rec` scoping,
  function patterns, `@`-patterns and the "args excludes defaults" rule,
  `__functor`, path literals, `let {}` body form):
  <https://nix.dev/manual/nix/2.24/language/syntax>
- Nix Reference Manual — String literals (double-quoted and indented-string
  escapes; common-indentation stripping; leading-newline elision; tabs not
  stripped):
  <https://nix.dev/manual/nix/2.26/language/string-literals>
- Nix Reference Manual — String interpolation (coercible value set; `__toString`
  takes precedence over `outPath`; path-copied-to-store; the path `/`-before-
  interpolation rule):
  <https://nix.dev/manual/nix/2.24/language/string-interpolation>
- Nix Reference Manual — String context (context element kinds, propagation):
  <https://nix.dev/manual/nix/2.33/language/string-context>
- Nix Reference Manual — Built-in Functions (`tryEval`, `throw`, `abort`,
  `seq`/`deepSeq` definitions — full contracts in doc 21):
  <https://nix.dev/manual/nix/2.34/language/builtins>
- NixOS Wiki — Error handling (`tryEval` catches `throw`/`assert` but not
  `abort`; `tryEval` does not deep-force; `deepSeq` to force nested errors):
  <https://wiki.nixos.org/wiki/Error_handling>
- NixOS Wiki — Nix Language Quirks (indented-string and scoping edge cases):
  <https://wiki.nixos.org/wiki/Nix_Language_Quirks>
- NixOS/nix #11188 — "Ban integer overflow in the Nix language" (overflow throws
  rather than wraps; released in Nix 2.25; negating `i64::MIN` also throws):
  <https://github.com/NixOS/nix/pull/11188>
- NixOS/nix #3371 — "Function equality is broken" (direct `f == f` is `false`,
  but a shared function nested in compared containers can compare equal by
  pointer/value identity — the wart to reproduce):
  <https://github.com/NixOS/nix/issues/3371>
- NixOS/nix #3759 — "Indented strings do not work with tabs":
  <https://github.com/NixOS/nix/issues/3759>
- NixOS/nix #7834 — "Tabs silently break indentation stripping":
  <https://github.com/NixOS/nix/issues/7834>
- A complete listing of Nix operators and their precedence (cross-check):
  <https://gist.github.com/joepie91/c3c047f3406aea9ec65eebce2ffd449d>
