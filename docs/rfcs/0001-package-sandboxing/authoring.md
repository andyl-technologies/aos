# Authoring packages: the `expose` attribute

Status: planning (direction resolved by investigation; exact schema open)
Siblings: [README.md](README.md) · [permissions.md](permissions.md) ·
[container-model.md](container-model.md) · [apm-integration.md](apm-integration.md) ·
[boot-activation.md](boot-activation.md) · [config.md](config.md) ·
[activation.md](activation.md) · [open-questions.md](open-questions.md)

Where do package definitions live? **Not** in a central `modules/packages/`
tree. Service integration is an **optional `expose` attribute on any package
derivation in `pkgs/`**, rendered at build time into eval-free artifacts, and
`modules/` shrinks to host policy. This doc records the decision, the verified
mechanics, and the precedent.

## The forcing function

`apm install` runs on a deployed host with **no Nix evaluator** — no
`lib.evalModules`, no fixpoint. Whatever a package needs at install time
(units, target, `[permissions]` manifest, container-root reference) must exist
as **build artifacts in its store output / registry metadata**. A central
module tree can only serve image-baked packages; runtime-installed ones would
need a second authoring path — the split-brain this doc set keeps warning
about. The integration must therefore be built *with the package*.

## What every ecosystem converged on

| | Who ships units | Who decides enablement | Install hooks |
|---|---|---|---|
| Debian | the .deb | `systemctl preset --preset-mode=enable-only` via deb-systemd-helper (post-bug-#772555) | imperative `postinst` (the cautionary tale) |
| Fedora/RHEL | the .rpm | allowlist presets (`90-default.preset`) + `systemd-update-helper`; scriptlets replaced by RPM file triggers | declarative triggers |
| Arch | the package | `99-default.preset` = `disable *`; never auto-enable | `.install` discouraged |
| nixpkgs Modular Services (merged 2025) | `passthru.services` on the derivation | host instantiates under `system.services.<name>` | n/a (eval) |

No ecosystem has a special "service package" type — units are ordinary,
optional package payload, and activation policy is lifted out of the package
into a central declarative layer (presets — see
[boot-activation.md](boot-activation.md) §3.2).

**nixpkgs Modular Services is the direct prior art** (PR NixOS/nixpkgs#372170,
merged July 2025, shipped NixOS 25.11; grown from RFC 163): after twenty years
of central `services.*` modules, nixpkgs' own conclusion was services as
package-attached values (`passthru.services`,
`finalAttrs.finalPackage`-coupled), flat named instances, composition by
import. Its motivation statement — services "were defined using sets of
options *in* modules, not *as* modules… problems with composability, reuse,
and portability" — is this doc set's problem statement verbatim. The AOS
difference: their service values are consumed by host-side eval; ours must
render to **eval-free, signable artifacts**, because of the forcing function
above. Its still-open future work — typed cross-service connections — is
exactly our Decision 18.

## Verified mechanics in the AOS tree

All ground-truthed against the current tree:

- **`mkDerivation` is ready** (`lib/derivations.nix:478–656`): it already has
  `passthru`, `overrideAttrs`, multi-output support, and a `removeAttrs`
  filter list. One required change: unknown attrs flow into
  `builtins.derivation` (env serialization), where a nested attrset fails — so
  `expose` must be **added to the filter list** (one line) and routed to the
  renderer instead. This also settles "one namespaced attr vs. N top-level
  args": every top-level key would be a permanent filter-list entry and a
  reserved word; one attr is one entry.
- **The optional-attr pattern already exists in-house**: `checks`
  (`default.nix:137–151`) is an optional per-package attribute enumerated via
  `builtins.attrNames pkgs` + `pkg ? checks`. `expose` is the second instance
  of an existing house pattern, not a new invention. Enumeration for
  fleet-spec and eval checks is `lib.filterAttrs (_: p: p ? expose) pkgs`.
- **The unit renderers are pure** (`lib/modules/systemd/lib.nix`,
  `render-role.nix`): `serviceToUnit`/`targetToUnit`/… take plain attrsets and
  are callable outside `evalModules`. Rendering `expose.units` at package
  build time reuses them as-is; typed validation comes from evaluating the
  `unit-options.nix` types over the attrset at render time.
- **Render as a cheap sibling derivation** (trivial builders exist:
  `pkgs/build-support/trivial-builders.nix`), surfaced as `pkg.expose` via
  `passthru` — so editing a unit re-renders text and never rebuilds the
  payload, and the payload's closure never references its own integration.
- **The name `expose` is free** (zero uses in `.nix` or `crates/`), and the
  obvious alternative `system` is **taken** — it is the core derivation
  platform attribute (`lib/derivations.nix:730`).

## Authoring shapes

Single-purpose software — integration on the payload derivation (the deb
shape: one package, payload + units + manifest):

```nix
{ mkDerivation, fetchurl, ... }:
mkDerivation {
  pname = "aos-registry-server";
  # ... build as today ...
  expose = {
    units."aos-registry-server.service" = { /* typed unit options */ };
    permissions = { network = "private"; };   # permissions.md
  };
}
```

Multi-profile software — **meta-packages** (the Debian pattern: a near-empty
payload + units + a dependency on the real package; `k3s-worker.deb` →
`Depends: k3s`):

```nix
k3s-worker = mkDerivation {
  pname = "k3s-worker";
  runtimeDeps = [ k3s ];        # payload is the dep edge
  phases = [ /* trivial */ ];
  expose = {
    units."k3s.service" = {
      serviceConfig = { ExecStart = "${k3s}/bin/k3s agent"; KillMode = "process"; /* … */ };
    };
    permissions = { network = "host"; /* … see permissions.md */ };
    requires = [ ];             # service deps by package NAME —
                                # container-model.md §Composition, Decision 18
  };
};
```

The agent/server divergence that lives in `k3s-worker.nix` vs.
`k3s-control-plane.nix` today moves here one-to-one; `_k3s-common.nix`
survives as a shared let-binding. Whether `expose` goes on the payload or a
meta-package is a per-package judgment call over **one** mechanism — not a
schema fork.

## What `modules/` keeps

The OS-policy layer, nothing else — the preset analog:

- `modules/packages.nix` — bake list (which packages' closures + inert units
  are in the image) and image preset policy
  ([boot-activation.md](boot-activation.md) §3.2).
- `modules/security/policy.nix` — permission tiers and the kernel-module
  allowlist (the host side of `request ∩ grant` —
  [permissions.md](permissions.md)).
- `modules/security/firewall.nix` — the base table, unchanged.

Roughly ~50 lines of policy replacing the ~400-line `roleType` machinery. The
`render-role.nix` rendering logic is not deleted — it relocates into the
package-side renderer.

## The signing constraint (a feature)

A package-owned artifact is static per version — it cannot read host config at
eval. That is exactly what the signed `[permissions]` manifest requires (a
manifest that varied per-host could not be registry-signed), and it matches
the distro norm: static units that read runtime config from `/etc`
([config.md](config.md)). The k3s modules already comply — `k3s.env` is
runtime config, not eval-time parameterization. Per-host variation is config
delivery, never unit-text variation.

## Open

- The exact `expose` schema (units / permissions / `requires` /
  container-root reference) — co-designed with the registry metadata
  ([apm-integration.md](apm-integration.md) §2) and gated on the schema
  capability-gate fix (Decision 19).
- Whether `expose.permissions` is validated at package build, at
  `apr publish`, or both (lean: both — build-time for authoring feedback,
  publish-time as the gate).
- Naming alignment with nixpkgs Modular Services (`passthru.services`) if AOS
  ever wants interop — cosmetic, defer.
