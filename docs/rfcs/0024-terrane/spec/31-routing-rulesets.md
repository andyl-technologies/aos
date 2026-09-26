# 31 — Routing rulesets

This file owns the **ruleset**: the closed-vocabulary, declarative
match-to-action policy that shapes how a view is realized. A ruleset lets a
policy author substitute a blessed program at every compiler entry point,
inject a file or socket at a path, prefetch a closure's children when its
root is opened, tag entries by content class, or deny access to entries whose
provenance fails a selector, without shipping code to the node that serves
the tree. Because Terrane trees are first-class values, most rule families
are tree transforms evaluated once at realization and committed as a derived
root; only prefetch and lazy content classification remain runtime behavior.
Rulesets are referenced from views by policy name ([`26-surfaces.md`](26-surfaces.md)
SURF-8) and encoded as portable policy objects.

## Model

A rule says: *when* (at which evaluation point), *if* (a matcher over the
entry's path, attributes, content class, membership in a named set, closure
relation, or provenance), *then* (one action), with a priority to break
ties. A ruleset is an ordered list of rules plus named policy sets.

```text
rule    := { when: on_realize | on_commit | on_access,
             match: <matcher>, do: <action>, priority: int, id: string }
ruleset := { rules: [rule…], sets: { name: [member…] }, selectors: { name: <selector> } }
```

The vocabulary of matchers and actions is closed. A new heuristic is a new
built-in matcher added to this specification, never a script, bytecode, or
callback supplied with the ruleset. The reason is the same one that keeps
surfaces closed: the process that realizes a view holds capabilities that a
policy author does not, and configuration must not become code.

The three evaluation points correspond to the three places a tree meets the
world:

- `on_realize`: when a view is realized for an exposure. Rules here are
  tree transforms (`remap`, `bind`, `guard`, `tag`) producing a derived
  root, and prefetch plans.
- `on_commit`: when a working tree is committed. Rules here classify and
  tag new entries and can guard what a commit may introduce.
- `on_access`: when a consumer first touches an entry whose bytes are not
  yet resident. This is the only point at which `content_magic` can inspect
  bytes that no writer has classified, and the only point at which
  `prefetch` fires in response to demand.

## Rule shape

- **[RULE-1]** A ruleset MUST be an ordered list of rules. Each rule MUST
  have a stable `id` unique within the ruleset, exactly one `when`, exactly
  one `match` tree, exactly one `do`, and an integer `priority` (default 0).
- **[RULE-2]** `when` MUST be one of `on_realize`, `on_commit`, or
  `on_access`. A rule with an action not permitted at its evaluation point
  (§ actions) MUST be rejected at ruleset compilation.
- **[RULE-3]** A ruleset MAY declare named **policy sets**: lists whose
  members are exact paths, glob patterns over paths, or content hashes. Sets
  are referenced by `set_member` matchers and by the set-algebra of
  § policy sets.
- **[RULE-4]** A ruleset MAY declare named **provenance selectors** for use
  by `provenance` matchers. Selector syntax is that of
  [`23-provenance-and-trust.md`](23-provenance-and-trust.md).

## Matchers

| Matcher | Arguments | Needs bytes | Meaning |
| --- | --- | --- | --- |
| `path_prefix` | prefix | no | path begins with prefix at a segment boundary |
| `path_glob` | pattern | no | path matches a shell-style glob (`*`, `**`, `?`, `[…]`) |
| `basename_set` | set of names | no | final path segment is in the set |
| `layout` | pattern with `<name>` | no | path matches a segment layout such as `*/bin/<name>` |
| `content_magic` | class | yes | the entry's content class (`elf`, `shebang`, `ar`, `zstd`, `gzip`, `tar`, `text`, `other`, as registered by [`10-derived-data.md`](10-derived-data.md)) |
| `set_member` | set name | no | path or object hash is a member of the named policy set |
| `closure_child_of` | matcher | no | entry is a descendant, via the tree's reference attributes, of an entry that matches the inner matcher |
| `object_attr` | name, value or pattern | no | the entry's attribute equals or matches |
| `provenance` | selector name | no | the entry's provenance satisfies the named selector |
| `all` | list of matchers | inherited | every child matches |
| `any` | list of matchers | inherited | at least one child matches |
| `not` | matcher | inherited | the child does not match |

- **[RULE-5]** An implementation MUST support every matcher in the table
  and MUST reject a ruleset that uses any other matcher name.
- **[RULE-6]** `content_magic` MUST be evaluated from the entry's
  `class.magic` derived attribute ([`10-derived-data.md`](10-derived-data.md))
  when present. Only when the attribute is absent, and only at `on_access`
  or `on_commit`, MAY an implementation classify from bytes; it MUST then
  record the result as the derived attribute so no later evaluation needs
  the bytes. At `on_realize`, an absent attribute MUST be treated as
  `unknown` and the entry MUST be reported in the ruleset's completeness
  status. *Gate:* `gate:ruleset-magic-memo`.
- **[RULE-7]** `closure_child_of` MUST be evaluated over the reference
  attributes recorded on entries by the writer or adapter (for example the
  NAR adapter's `nar.references`) and MUST NOT require content.
- **[RULE-8]** Matchers MUST be pure functions of the entry, its attributes,
  its provenance, the ruleset's sets, and (for `content_magic` from bytes)
  the entry's content. They MUST NOT depend on time, host, or access
  history.

## Actions

| Action | Arguments | Permitted at | Effect |
| --- | --- | --- | --- |
| `remap` | target object reference | `on_realize` | the matched entry's content is replaced by the blessed target in the derived root; the original entry is retained at its original path if `keep_original` (default true) and an attribute records the remap |
| `bind` | source (blessed object, or a socket or file the serving instance provides by registered name) | `on_realize` | an entry is added or replaced at the matched path presenting the source |
| `guard` | `allow` or `deny` | `on_realize`, `on_commit`, `on_access` | at realize: the entry is filtered from the derived root on `deny`; at commit: a `deny` rejects the commit; at access: a `deny` fails the access |
| `tag` | attribute name and value | `on_realize`, `on_commit` | the attribute is set on the matched entry in the derived root or committed tree |
| `prefetch` | scope (`entry`, `directory`, `closure`), priority, byte cap | `on_realize`, `on_access` | the named scope is scheduled for fetch at the given priority |

- **[RULE-9]** An implementation MUST support every action in the table and
  MUST reject any other action name.
- **[RULE-10]** `remap` and `bind` targets MUST be **blessed**: an object
  reference already reachable under a root the exposure's token can read, or
  a source name registered with the serving instance. A ruleset MUST NOT
  carry bytes, and a target that is not blessed MUST fail compilation.
  *Gate:* `gate:ruleset-blessed-targets`.
- **[RULE-11]** `remap` MUST NOT alter any entry other than the matched
  entry. Where a remapped program needs the original (for example a
  compiler wrapper that execs the real compiler), the original remains at
  its own unchanged path and the remap attribute names it.
- **[RULE-12]** `guard` at `on_realize` MUST be evaluated before any other
  rule family so that a denied entry is never remapped, bound, tagged, or
  prefetched. A `guard` evaluation error MUST fail closed (`deny`).
- **[RULE-13]** `prefetch` is advisory. A dropped, failed, or evicted
  prefetch MUST NOT fail or block any access. A `prefetch` at `on_access`
  MUST be rate-limited by the byte cap of the rule and the exposure's
  overall prefetch budget.
- **[RULE-14]** `tag` MUST NOT overwrite a derived attribute that the
  specification defines as computed from content (for example `hash.sha256` or
  `class.magic`); it MAY set attributes in the `tag.` namespace and
  attributes the exposure's schema declares writable.

## Evaluation

- **[RULE-15]** For each entry at each evaluation point, rules MUST be
  evaluated in this order: all `guard` rules first; then remaining rules by
  path specificity (a rule whose path matcher matches a longer prefix, or a
  glob with more literal segments, is more specific); then by descending
  `priority`; then by position in the ruleset. The first `remap` or `bind`
  that matches an entry wins for that entry; `tag` and `prefetch` rules all
  fire. *Gate:* `gate:ruleset-eval-order`.
- **[RULE-16]** A ruleset MUST be compiled before use into a form in which
  path matchers are a prefix trie, `basename_set` and `set_member` are hash
  lookups, and `content_magic` is evaluated only after some cheaper matcher
  in the same rule has already matched. A ruleset that cannot be compiled
  MUST be rejected at exposure start.
- **[RULE-17]** Evaluation results for `remap`, `bind`, `tag`, and
  `prefetch` rules MUST be memoized by `(evaluation point, path, object
  hash, ruleset hash)`. Results for `guard` rules and for any rule with a
  `provenance` matcher MUST NOT be memoized across exposures, because their
  outcome depends on the exposure's token and trust selectors.
- **[RULE-18]** Every fired rule MUST emit a decision record containing the
  rule `id`, evaluation point, path, object hash, action, and outcome, to
  the exposure's decision log ([`34-observability.md`](34-observability.md)).
  A consumer holding `read` on the view MUST be able to query the log for a
  path to answer "which rule affected this entry".

## Policy sets and set algebra

The characteristic use of sets is to let a human override a heuristic in
both directions: force an entry into a class the matcher missed, or exclude
one the matcher wrongly caught.

```text
candidates = (detected ∪ allowlist) \ denylist
```

- **[RULE-19]** A rule that uses `any[<heuristic>, set_member(allowlist)]`
  together with `not(set_member(denylist))` MUST compute exactly the set
  above. Implementations MUST evaluate set membership before the heuristic
  so that a denylisted entry never triggers content classification.
- **[RULE-20]** Sets referenced by a ruleset MUST be declared in the same
  ruleset or inherited from a parent policy object; a reference to an
  undeclared set MUST fail compilation.

## Collapse to tree algebra

At `on_realize`, the effect of a ruleset on a view is a derived root:

```text
realized_root = map(filter(root, ¬guard_deny), remap ∪ bind ∪ tag)
```

- **[RULE-21]** An implementation MUST produce the `on_realize` result as a
  derived root using the tree algebra of
  [`07-tree-algebra.md`](07-tree-algebra.md): `filter` for guards, `map`
  for remap, bind, and tag. The derived root MUST be recorded with its
  recipe `(root hash, ruleset hash, blessed target hashes)` and memoized so
  that realizing the same view under the same ruleset never re-evaluates
  rules. *Gate:* `gate:ruleset-derived-root`.
- **[RULE-22]** The derived root MUST NOT be committed to the view's ref; it
  is a realization artifact keyed by recipe, and the view's served commit
  (SURF-27) remains the source commit. An implementation MAY commit derived
  roots to a `refs/derived/…` namespace for sharing across hosts.
- **[RULE-23]** Only `prefetch` and `content_magic`-from-bytes MAY execute
  at `on_access`. An implementation MUST NOT perform remap, bind, or tag at
  access time; if such a rule depends on a `content_magic` result that was
  unknown at realize, the entry MUST be treated as unmatched for that
  realization and the ruleset's completeness status MUST report it.
- **[RULE-24]** `on_commit` rules MUST be evaluated on the delta of the
  commit only ([`07-tree-algebra.md`](07-tree-algebra.md) `diff`), never on
  the whole tree.

## Encoding

- **[RULE-25]** A ruleset MUST be encoded as a portable policy object in the
  deterministic CBOR profile of
  [`reference/terrane-v1.cddl`](reference/terrane-v1.cddl) under the media
  type registered for rulesets, and MUST be referenced from a view's policy
  by its content hash. A ruleset's hash is part of every derived-root recipe
  (RULE-21) and every memo key (RULE-17).
- **[RULE-26]** A ruleset object MUST NOT contain executable content of any
  kind, and an implementation MUST reject an object whose schema contains
  unknown keys (decoder limits and unknown-key rejection follow the profile
  rules).
- **[RULE-27]** Rulesets MAY inherit: a policy object MAY name a parent
  ruleset by hash, in which case the child's rules are appended after the
  parent's and the child's sets extend the parent's. A cycle MUST fail
  compilation.
- **[RULE-28]** A ruleset MAY be updated for a running exposure by
  replacing the view's policy. Replacement MUST re-derive the realized root
  and switch the exposure to it atomically as for a `follow` ref advance
  (FUSE-35, EROFS-11). Memoized results keyed by the old ruleset hash are
  unaffected.

## Informative: example

```toml
# Substitute a distributed-compilation launcher for every C and C++
# compiler entry point, keep the real compilers in place, prefetch what a
# compiler needs, and refuse anything not built by a trusted builder.

[[rule]]
id = "deny-untrusted"
when = "on_realize"
match = { not = { provenance = "trusted-builders" } }
do = { guard = "deny" }

[[rule]]
id = "cc-shadow"
when = "on_realize"
priority = 10
match = { all = [
  { layout = "*/bin/<name>" },
  { any = [
      { basename_set = ["cc", "gcc", "g++", "clang", "clang++", "c++"] },
      { set_member = "cc-allowlist" } ] },
  { not = { set_member = "cc-denylist" } },
  { content_magic = "elf" } ] }
do = { remap = { target = "commit:9c1f…:/launchers/cc-shim", keep_original = true } }

[[rule]]
id = "cc-prefetch"
when = "on_access"
match = { object_attr = { name = "tag.class", value = "compiler" } }
do = { prefetch = { scope = "closure", priority = "low", byte_cap = 268435456 } }

[sets]
cc-allowlist = ["/nix/store/*-gcc-wrapper-*/bin/gcc"]
cc-denylist  = ["/nix/store/*-rustc-*/bin/rustc"]

[selectors]
trusted-builders = "all(issuer(\"builders.example\"), source(built))"
```

## Interactions

- [`07-tree-algebra.md`](07-tree-algebra.md): `filter` and `map` are the
  realization of rules.
- [`10-derived-data.md`](10-derived-data.md): `class.magic` and other
  derived attributes are what matchers read.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md): provenance
  selectors.
- [`26-surfaces.md`](26-surfaces.md): rulesets reach a surface through the
  view's policy name.
- [`27-surface-fuse.md`](27-surface-fuse.md): `on_access` evaluation happens
  in the serve process on the open path.
- [`34-observability.md`](34-observability.md): decision logs.
- [`reference/terrane-v1.cddl`](reference/terrane-v1.cddl): the ruleset
  object schema.
