# Module system: namespacing, dependency inference, eval semantics

This document specifies how packages are namespaced as modules, how the
dependency graph is composed by inference (no hand-authored TOML edges), and the
eval-semantics policy that must be defined rather than left emergent. Line
citations are to `lib/modules.nix`, `lib/types.nix`, and `lib/default.nix`.

## Namespacing: per-package roots + privileged shared roots

Options live in a two-tier namespace:

- **Per-package roots — `{pkg}.*`.** Each package's `config` module is mounted
  as a submodule under its own name, declaring its private option surface and
  its `{pkg}.enable`. Ownership is **structural**: the root segment *is* the
  declaring package, so "who declares `redis.maxmemory`" is answered by the
  root, with no index. This is the existing `attrsOf (submodule …)` +
  name-injection idiom (`lib/types.nix:564`, `lib/default.nix:77-88`,
  `lib/modules/systemd/types.nix:71-91`).

- **Shared / extension roots — `firewall.*`, `dns.*`, `nginx.*`.** Neutral
  options that many packages write and read. Each is declared by exactly one
  **owner**. An owner is a **system extension**: it declares the interface
  (option schema + merge semantics); other packages write into it to compose;
  consumers read it. Ownership of a shared root is exclusive and registered.

"The system" is not a separate category: the base lib is simply the subset of
extensions that ships **in the image** and is **implicitly trusted**. So a
shared root varies on two axes — delivery (image-bundled vs registry-fetched)
and trust (implicit vs key-gated). `systemd.*` (base lib, image-bundled) and
`firewall.*` (a registry extension, key-gated) are the same kind of thing.

**The principled line for what must be base vs fetched:** does the toplevel
renderer/activation itself consume the option? `systemd.*`, `environment.etc.*`,
`users.*` — yes, the renderer cannot produce units or `/etc` without them, so
they are structural-core and image-bundled. `firewall.*`, `dns.*` — consumed
only by other packages, so they can be key-gated fetched extensions that version
their interface independently. This keeps the ABI-stable, image-bound surface
minimal (see [`generations.md`](generations.md) for `module_abi`).

### How "who declares it" is answered

| Root kind | Lookup | Mechanism |
|-----------|--------|-----------|
| `{pkg}.*` (private) | the package named in the root | **structural** — root = package name, no index |
| `firewall.*` (shared) | the registered exclusive owner | **root-ownership registry** (`root → owner@version`) |
| `system.capabilities.X` (token) | anyone who *sets* it | **write-provider index** (many setters) |

Exclusivity is enforced at publish/resolve: a package declaring `firewall.*` is
rejected if another package already owns that root, unless it is a successor
version (or a registered variant — see [Variants](#variants-and-alternatives)).
Declaring a shared root that others write into is privileged: only packages
signed by a trusted system-extension key (or operator-allowlisted) may claim
one, and each shared root carries its own `module_abi` so interfaces evolve
independently.

## Dependency inference — no hand-authored TOML edges

The dependency graph is a function of `options` declarations × `config`
reads/writes across the resolved set, plus a registry-wide inverted index. The
hand-maintained `expose.requires` package-name edge list is **removed**.

### Provides — derived, not declared

The options a module **declares** are its `provides`. They are extracted by an
**options-only evaluation** that does not force `config`: `options.path.{type,
default, isDefined, definitions}` do not force the merge; only `.value` does
(`lib/modules.nix:924-930`, real precedent at `lib/testing/eval.nix:20`). At
publish, each package's `config` module is options-evaluated in isolation
(base lib injected) to derive its declared option paths, stored registry-wide as
the inverted index `option-path → package@version`. This is mechanical and
trustworthy — computed, not claimed.

### Requires — discovered, never hand-declared

Option **reads/writes** cannot be statically inferred (they are arbitrary
expressions behind `mkIf`). Two mechanical discovery paths, both edge-free:

1. **Publish-time AST scan** for `config.<path>` / `options.<path>` access
   patterns → an over-approximate requires set. Conservative (misses computed
   `config.${name}` paths), needs no evaluator, pre-closes the set.
2. **Error-driven resolve↔eval fixpoint** (the backstop, and what makes stock
   Nix sufficient — see [`architecture.md`](architecture.md)). The strict module
   system already throws naming the missing option
   (`lib/modules.nix:744` "The option 'X' is used but has no definition…";
   `:917` "option(s) are not declared"). The resolver parses the path, looks it
   up in the inverted index, fetches the provider, and re-evals — to a fixpoint:

   ```text
   eval → throw names missing option X → index[X] → fetch provider → re-eval → …
   ```

This is sound *because* the system always eval-then-activates: conditional reads
that only fire under some config are discovered on the next resolve↔eval cycle,
which fetches the provider on demand. The resolver carries a causal chain so a
non-converging loop dumps an iteration trace rather than hanging (see
[`operability.md`](operability.md)).

### What inference cannot cover — the valuation floor

Read/declare matching conflates "X is declared" (always true if some module
declares it — defaults exist) with "X is set to a meaningful value by some
provider." A consumer that needs *a live DNS resolver*, not just the
`networking.nameservers` default, is satisfied structurally but not
semantically. This is the one residual signal, expressed without a TOML edge as
either:

- a **capability token** a provider sets (`system.capabilities.dns-resolver =
  true`), which the resolver can auto-close via the write-provider index; or
- an **in-module assertion** (`assertions = [{ assertion = anyResolverEnabled;
  … }]`), which fails the generation but cannot fetch a provider.

## Eval-semantics policy

These are defined policy, not emergent behavior. The default `str`/`enum` merge
is `lastValue` ("take the last def in evaluation order", `lib/types.nix:26-29,
192-197`), and evaluation order is `[internalModule] ++ modules` flattened
depth-first (`lib/modules.nix:642`) — so leaving precedence to ordering is
exactly the emergent behavior to eliminate.

### Merge precedence — operator > package > default, via reserved bands

The engine assigns each def a `_priority` (bare = 100), takes `minPriority`, and
merges only the survivors; lower number wins (`lib/modules.nix:695, 700-711,
99-106`). Reserve bands:

| Priority | Tier |
|----------|------|
| 50 (`mkForce`) | break-glass, reserved (forbidden on owned/shared roots by publish policy) |
| **75** | **operator tier — `host.nix` bare defs** |
| 100 | package normal contributions |
| 1000 (`mkDefault`) | base / package defaults |

`host.nix` bare definitions are lifted to priority **75** (between `mkForce` and
normal), so the operator deterministically beats any package contribution
regardless of module order. **Implementation: file-provenance priority tagging.**
The engine already threads each def's source `file` (`lib/modules.nix:669`); at
the priority-assignment step (`:695`), bare defs whose `file` is the registered
`host.nix` get priority 75 instead of 100. ~3 lines, declarative.

> **Trap (do not):** lifting by wrapping the host.nix *subtree*
> (`redis = mkOverride 75 { … }`) silently drops the nested def —
> `collectDefsAtPath` traverses `mkIf`/`mkMerge` but **not** override markers
> during descent (`lib/modules.nix:298-328`), so it finds no leaf under the
> marker node. The override must sit at the leaf, or use the file-provenance
> approach above.

### Host facts — declared inputs under `host.facts.*`, not `specialArgs`

Host facts (hostname, networking-by-MAC, disk IDs) are intentionally
host-varying, but `--pure-eval` blocks ambient reads (`getEnv`,
`currentSystem`), so there is no hidden channel — `host.nix` is the one declared
input. Facts enter **only** as typed config under a privileged-owned
`host.facts.*` root:

- `host.facts.hostname` → `nonEmptyStr`
- `host.facts.interfaces` → `attrsOf (submodule …)` keyed by MAC (the key is
  injected as `name`, `lib/default.nix:81-88`)
- `host.facts.disks` → `attrsOf` keyed by disk-id

`specialArgs` is rejected for this: its values are untyped, unmerged,
provenance-less, and never appear in the manifest (`lib/modules.nix:546, 620`).
Facts are a data contract; they must be typed, visible, and assertable. This is
what reconciles "deterministic given declared inputs" with per-host variation:
eval is a pure function of `(modules + host.nix data)`.

### Conflicts on shared roots — loud, not silent

- **Multiple declarers of one owned root → rejected at publish.** The engine
  does not merge declarations — `optionMap` is `acc // {key = decl}`
  (`lib/modules.nix:657-664`), so a second declarer silently *shadows* the
  first. The owner registry rejects two packages declaring overlapping owned
  roots, citing both sources.
- **List contributions merge** by concatenation + `mkBefore`/`mkAfter`
  (`lib/types.nix:349-393`) — no conflict by construction. (`firewall.allowedTCP
  += [443]` from any package.)
- **Conflicting scalars at equal priority → error, not last-wins.** The owner
  of a shared scalar declares it with a conflict-rejecting merge: `uniq (enum
  [...])` (`lib/types.nix:644-658`) or `mergeEqualOption` (`:155-164`), which
  throw "conflicting definitions" listing every def with its `file`. So
  `firewall.forwardPolicy = uniq (enum [ "accept" "drop" … ])`; a genuine
  disagreement is resolved only by an explicit priority bump — legitimately the
  operator at tier 75.

### Enablement and conscription

The security target is *foreign conscription*: a package silently expanding
attack surface the operator never authorized (`redis-exporter` starting `redis`
and opening 6379). The rule forbids that without banning legitimate provider
configuration:

- **A package may write/enable only within roots it owns or is a registered
  provider/contributor of.** Writing into a *foreign* root it neither owns nor
  is registered against is rejected at publish, detected from the per-def `file`
  provenance (`lib/modules.nix:669`) + the owner/provider registry.
- **Foreign top-level service enable is forbidden.** `redis-exporter` cannot set
  `redis.enable`. It declares its dependency as a **resolve-time assertion**
  ("`redis-exporter` requires `redis.enable = true`; set it in `host.nix`"),
  collected at `lib/modules.nix:935` and enforced when the manifest is forced.
  The requirement is discoverable; the operator stays in control.
- **Provider enablement is allowed.** A registered provider of a shared root may
  set defaults and enable the sub-features it ships *within that root* —
  `nginx-full` setting `nginx.modules.http3.enable = true`. This is not
  conscription: `nginx-full` *is* an nginx provider (see
  [Variants](#variants-and-alternatives)), so it configures its own interface.
- **Top-level `{service}.enable` stays operator-owned.** Installing a provider
  does not start its service (NixOS-style: install ≠ enable). `apm install
  nginx-full` starting nginx is modeled as the *operator's* install action
  injecting `nginx.enable = true` into `host.nix` — operator intent, not package
  conscription.
- **The operator always overrides** any provider-set sub-flag at tier 75.

### Variants and alternatives

A logical service is a shared root (`nginx.*`); concrete packages that implement
it (`nginx-full`, `nginx-minimal`, `nginx-light`) are **alternative providers**:
they `Provides` the virtual root and `Conflicts` with each other, so exactly one
is in any resolved set. Consequences:

- The single-declarer rule (above) holds **per resolved set** via the conflict —
  multiple variants may exist in the registry, but only one declares/implements
  `nginx.*` on any host.
- The installed variant **is** nginx for configuration: the operator enables the
  service with `nginx.enable` and selects the implementation by which variant is
  installed. The variant may enable the sub-features it ships within `nginx.*`.
- A *layering* relationship (a base `nginx` package + an `nginx-full` extension
  that adds and enables modules, both installed) is the same mechanism with
  `nginx-full` as a registered **contributor** to `nginx.*` rather than a
  mutually-exclusive variant. Either way the authorization is the registry
  registration, checked at publish.

## What the existing module system already provides

Confirmed present (no new machinery), with citations: options-only eval
(`lib/modules.nix:924-930`); submodules under dynamic roots with name injection
(`lib/types.nix:564`, `lib/default.nix:77-88`); freeform + `strict` modes that
throw on undeclared paths (`lib/modules.nix:591-614, 813-922`); base-lib
injection via `extraArgs`/`specialArgs`/`_module.args` (`:541-567, 620`);
priority merge (`:19-30, 700-711`); assertions/warnings (`:934-936`);
undefined-option throws naming path + file (`:744, 917`). The one capability not
natively available is **read-access instrumentation** — assigned to aos-nix in
P2; P1 uses the AST scan + error-driven fixpoint instead.
