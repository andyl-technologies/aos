# Module system: namespacing, dependency inference, eval semantics

This document specifies how packages are namespaced as modules, how the
dependency graph is composed by inference (no hand-authored TOML edges), and the
eval-semantics policy that must be defined rather than left emergent. Line
citations are to `lib/modules.nix`, `lib/types.nix`, and `lib/default.nix`.

## Namespacing: per-package roots + owned shared roots

Options live in a two-tier namespace:

- **Per-package roots — `{pkg}.*`.** Each package's `config` module is mounted
  as a submodule under its own name, declaring its private option surface and
  its `{pkg}.enable`. Ownership is **structural**: the root segment *is* the
  declaring package, so "who declares `redis.maxmemory`" is answered by the
  root, with no index. This is the existing `attrsOf (submodule …)` +
  name-injection idiom (`lib/types.nix:564`, `lib/default.nix:77-88`,
  `lib/modules/systemd/types.nix:71-91`).

- **Shared / extension roots — `firewall.*`, `dns.*`, `nginx.*`.** Neutral
  options that many packages write and read. Each is owned by exactly one
  **installed** package. An owner is a **system extension**: it declares the
  interface (option schema + merge semantics); other packages write into it to
  compose; consumers read it. Ownership of a shared root is exclusive
  **per-system** — an attribute of the composed image plus the installed set,
  never adjudicated by the registry.

"The system" is not a separate category: the base lib is simply the subset of
extensions that ships **in the image** and is **implicitly trusted**. So a
shared root varies on two axes — delivery (image-bundled vs registry-fetched)
and trust (implicit vs operator install decision). `systemd.*` (base lib,
image-bundled) and `firewall.*` (a registry extension the operator installs) are
the same kind of thing.

**The principled line for what must be base vs fetched:** does the toplevel
renderer/activation itself consume the option? `systemd.*`, `environment.etc.*`,
`users.*` — yes, the renderer cannot produce units or `/etc` without them, so
they are structural-core and image-bundled. `firewall.*`, `dns.*` — consumed
only by other packages, so they can be operator-installed fetched extensions that
version their interface independently. This keeps the ABI-stable, image-bound surface
minimal (see [`generations.md`](generations.md) for `module_abi`).

### How "who declares it" is answered

| Root kind | Lookup | Mechanism |
|-----------|--------|-----------|
| `{pkg}.*` (private) | the package named in the root | **structural** — root = package name, no index; missing-option lookup is a registry by-name metadata lookup |
| `firewall.*` (shared) | the installed owner | **system roots map** — locally derived from the installed set's `owns_roots` (`root → installed owner`) |
| `system.capabilities.X` (token) | anyone who *sets* it | **installed-set write-provider map** — union of installed `provides_capabilities` |

Exclusivity is enforced **per-system, at resolve time** (and optionally early at
install): two installed packages owning the same root is a hard error citing
both. The registry never adjudicates ownership — two registry packages may each
claim `firewall`; a system simply cannot install both. There is no publish-time
"privileged claim": trust moves to the **operator's install decision** (and
install-time key policy), not a system-extension key that gates a shared root at
publish. Each shared root still carries its own `module_abi` so interfaces evolve
independently. A read/write against a shared root with **no installed owner** is
a terminal, legible error (`"no installed package owns root 'firewall'"`); the
operator installs an owner — the resolver never auto-fetches one. See
[Variants](#variants-and-alternatives) for successor/variant handling.

## Dependency inference — no hand-authored TOML edges

The dependency graph is a function of `options` declarations × `config`
reads/writes across the resolved set, dispatched through the locally-derived
system roots map and structural package-name convention. The hand-maintained
`expose.requires` package-name edge list is **removed**.

### Provides — derived, not declared

The options a module **declares** are its `provides`. They are extracted by an
**options-only evaluation** that does not force `config`: `options.path.{type,
default, isDefined, definitions}` do not force the merge; only `.value` does
(`lib/modules.nix:924-930`, real precedent at `lib/testing/eval.nix:20`). At
publish, each package's `config` module is options-evaluated in isolation
(base lib injected) to derive its declared option paths, retained as
**per-package metadata** (`ConfigModuleMeta.declares`, looked up by name from
`registry.toml`). It is **not** aggregated into any cross-package registry-wide
structure. This is mechanical and trustworthy — computed, not claimed.

### Requires — discovered, never hand-declared

Option **reads/writes** cannot be statically inferred (they are arbitrary
expressions behind `mkIf`). Two mechanical discovery paths, both edge-free:

1. **Publish-time AST scan** for `config.<path>` / `options.<path>` access
   patterns → an over-approximate requires set. Conservative (misses computed
   `config.${name}` paths), needs no evaluator, pre-closes the set.
2. **Error-driven resolve↔eval fixpoint** (the backstop, and what makes stock
   Nix sufficient — see [`architecture.md`](architecture.md)). **Two distinct
   missing-option cases need two detectors (review M-read-absent)** — the strict
   throws name only some of them:
   - **Write to an undeclared option** (`{pkg}` sets `firewall.*`, no firewall
     module present) → the strict-mode throw `:917` ("option(s) are not
     declared") names the path. Caught directly.
   - **Read of an absent root** (`{pkg}` reads `config.firewall.forwardPolicy`,
     firewall absent) → this surfaces as a raw `attribute 'firewall' missing`,
     *not* `:744` (which fires only for a *declared* option lacking a value — the
     provider is already present). The resolver detects it from the naked
     attribute error and dispatches on the **root segment** (`firewall`) rather
     than relying on a single full-path throw string.

   In both cases the resolver dispatches on the option's **root segment**: a
   shared root resolves to its installed owner via the system roots map (or is
   the terminal "no installed package owns root" error); otherwise the root is
   structural (root = package name) and a registry **by-name** lookup fetches
   that package. It then re-evals — to a fixpoint:

   ```text
   eval → (strict throw | missing-attr) names root X →
     SystemRoots[X] ? installed owner : registry-by-name(X) → fetch provider → re-eval → …
   ```

   Parsing human-readable throw strings is an acknowledged fragility. The
   parser is isolated and exhaustively covered by fixtures.

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
  true`), which the resolver satisfies from the **installed-set write-provider
  map** (the union of installed packages' `provides_capabilities`). An unmet
  token is a **terminal resolve assertion** — the resolver never auto-fetches a
  setter; the operator installs one. (A registry hub may *suggest* candidates —
  "install one of: …" — but that is an optional, non-load-bearing search
  facility, not part of resolution.) Or
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
regardless of module order. **Implementation: provenance from the *authenticated
fetch source*, not module-supplied `_file` (review M-forgeable-file).** A
module's own `_file` is forgeable — a package can inject
`imports = [ { _file = "<registered host.nix path>"; … } ]` and `collectModules`
will eval it (`lib/modules.nix:637`), so keying priority on the engine's threaded
`file` (`:669`) would let any package **forge operator priority** *and* defeat
conscription detection. Instead the **resolver** stamps each def's provenance
from where it was loaded — the policy-accepted `host.nix` store path vs. a signed
package identity — and the engine reads *that* (a resolver-supplied, non-module
attribute) at the priority-assignment step (`:695`), ignoring any module-supplied
`_file`. Same rule governs conscription (next sections).

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

- **Two installed owners of one shared root → hard error, per-system.** The
  engine does not merge declarations — `optionMap` is `acc // {key = decl}`
  (`lib/modules.nix:657-664`), so a second declarer silently *shadows* the
  first. Building `SystemRoots` rejects two **installed** packages owning the
  same root, citing both sources. The registry never adjudicates this: two
  registry packages may both claim a root, but a single system cannot install
  both (enforced at resolve, optionally early at install).
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

> **Resolved decision F3 (review conscription-vs-composition).** "Forbid
> foreign-root writes" would reject *legitimate composition* — `nextcloud` writing
> `nginx.virtualHosts.*` / `postgresql.ensureDatabases` / `redis.*` is a
> foreign-root write — while an unscoped "registered contributor" escape is the
> same act an attacker uses, making the rule too strict or vacuous. The
> implemented resolution (F3-B in [`decisions.md`](decisions.md)) is a
> **capability-scoped contribution surface**: the shared-root *owner* declares
> which sub-paths non-owners may contribute (`nginx` opens `virtualHosts.*` /
> `upstreams.*`, keeps `enable`/global owner-only). Composition works; enabling or
> conscripting the service stays blocked. The bullets below specify that model.

- **A package may write/enable only within roots it owns, or within the
  owner-declared *contributable sub-paths* of a shared root.** A write outside
  those (a foreign root, or an owner-only sub-path like `enable`) is rejected at
  **resolve time**, detected from the **resolver-assigned provenance**
  (authenticated package identity, *not* module `_file` — see precedence above)
  checked against the installed owner's contributable surface in `SystemRoots`
  (`RootContribution.paths ⊆ RootOwner.contributable`). Publish-side lints may
  still check a package's *own* metadata, but the foreign-write/conscription
  check is per-system and no longer runs against a global index.
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
each package's authenticated `owns_roots = [ nginx ]` claim is its `Provides`,
and `SystemRoots` owned-root exclusivity is the resolved-set `Conflicts` rule.
The operator explicitly installs one concrete package by name. Per the F3-B
index-removal decision, a missing shared root never triggers registry discovery
or an automatic choice between alternatives. Consequences:

- The single-declarer rule (above) holds **per resolved set** via the conflict —
  multiple variants may exist in the registry, but only one declares/implements
  `nginx.*` on any host.
- The installed variant **is** nginx for configuration: the operator enables the
  service with `nginx.enable` and selects the implementation by which variant is
  installed. The variant may enable the sub-features it ships within `nginx.*`.
- A *layering* relationship (a base `nginx` package + an `nginx-full` extension
  that adds and enables modules, both installed) is the same mechanism with
  `nginx-full` as a registered **contributor** to `nginx.*` rather than a
  mutually-exclusive variant. Either way authorization comes from the signed
  package metadata and the operator's install decision, checked against the
  locally composed `SystemRoots` at resolve time.

## What the existing module system already provides

Confirmed present (no new machinery), with citations: options-only eval
(`lib/modules.nix:924-930`); submodules under dynamic roots with name injection
(`lib/types.nix:564`, `lib/default.nix:77-88`); freeform + `strict` modes that
throw on undeclared paths (`lib/modules.nix:591-614, 813-922`); base-lib
injection via `extraArgs`/`specialArgs`/`_module.args` (`:541-567, 620`);
priority merge (`:19-30, 700-711`); assertions/warnings (`:934-936`);
undefined-option throws naming path + file (`:744, 917`). Stock Nix does not
provide read-access instrumentation, so the driver uses the AST scan and
error-driven fixpoint.
