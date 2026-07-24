# RFC-0011: On-host, eval-only configuration — generations from downloaded Nix modules

- **Status:** Accepted, revised after an adversarial review, and **made
  goal-mode-executable**. The three forks (F1/F2/F3) and the generations open
  questions are now **resolved** with locked choices + decision-free mechanisms
  ([`decisions.md`](decisions.md)); field-level interface/schema contracts are in
  [`build-spec.md`](build-spec.md); and every implementation-plan item has a
  definition-of-done in [`acceptance-criteria.md`](acceptance-criteria.md). F1 is
  resolved as **dm-verity on the erofs root with the roothash baked into the
  measured UKI `.cmdline`** (so PCR-11 transitively covers the evaluator +
  base-lib), reusing the existing `package-root-image.nix` verity recipe.
  Implementation is phased: **P1** runs the existing from-source stock C++ Nix
  (`pkgs/tools/nix.nix`, 2.24.12) as the on-host evaluator; **P2** swaps in
  `aos-nix` ([RFC-0007](../0007-nix-evaluator/)) behind the same
  `eval → manifest` seam with no change to the registry format, the module
  contract, or the generation machinery. The phased checklist lives in
  [`implementation-plan.md`](implementation-plan.md).
- **Date:** 2026-06-25
- **Audience:** anyone working on `lib/modules.nix`, `lib/types.nix`,
  `lib/modules/systemd/`, `modules/base/{build,apm,apm-registries,networking}.nix`,
  `modules/base/activate.sh.in`, `modules/services/ignition.nix`,
  `modules/security/secure-boot.nix`, `crates/aos-package/`, `pkgs/tools/nix.nix`,
  `pkgs/build-support/_expose-renderer.nix`, or release/key operations.

This is a directory RFC. The README carries the status header, the core model,
the invariants, and the resolved decisions; the topic files hold the detail:

- [`architecture.md`](architecture.md) — the two-stage evaluation model, the
  render/assemble split that keeps "no build on host" honest, the `config`
  output, the manifest data contract, the evaluator (stock Nix → aos-nix), and
  the boot / first-boot bootstrap ordering.
- [`module-system.md`](module-system.md) — namespacing (per-package roots plus
  "system extension" packages that own shared roots, ownership adjudicated
  per-system at install/resolve), dependency inference (`provides` derived,
  `requires` discovered), the eval-semantics
  policy (precedence bands, host facts, conflict rejection, conscription), and
  the `module_abi` contract.
- [`generations.md`](generations.md) — the two-axis **image-generation ×
  config-generation** model, upgrade and rollback ordering across both axes,
  and ABI binding.
- [`trust-and-secrets.md`](trust-and-secrets.md) — why the locally-computed
  manifest is trustworthy without its own signature, the measured-vs-derived
  boundary, host configuration trust, the generation-attestation record, and the
  secrets-out-of-manifest interface to the forthcoming secret-management system.
- [`provisioning.md`](provisioning.md) — removing Ignition: systemd-native
  substrate (`systemd-repart`/`cryptenroll`/`tmpfiles`/`sysusers`), the
  idempotent-vs-one-shot principle and its guarded-unit rendering, the
  `aos metadata` agent (literal-Nix user-data, authenticated first-boot storage
  plans, the platform parity surface), and the convention substrate.
- [`orchestration.md`](orchestration.md) — compiling the eval output into a
  systemd unit/target graph: runtime units in `/run/systemd/system`, templated
  per-package fetch/install instances, `Wants=`-driven degraded boot, the
  recovery ladder, and the single atomic-commit point.
- [`operability.md`](operability.md) — `apm switch --dry-run` + the off-host CI
  preflight, eval-failure observability, GC of config closures, the
  flat-merge ↔ module-eval parity gate, and the perf budget + test plan.
- [`test-plan.md`](test-plan.md) — the **characterization-first TDD** strategy:
  the preserve-vs-change split, the three golden/snapshot artifacts written and
  green on master *before* implementation (the first code into the PR), the
  barrier pattern, and the red-first new-subsystem test specs.
- [`implementation-plan.md`](implementation-plan.md) — the phased checklist.
- [`decisions.md`](decisions.md) — the **locked resolutions** of F1/F2/F3 + the
  generations open questions, each with a decision-free mechanism.
- [`build-spec.md`](build-spec.md) — **field-level interface/schema contracts**
  (manifest, config output, per-package config-module metadata and the derived
  `SystemRoots`, the resolver fixpoint algorithm, the
  unit-graph compiler, the metadata `PlatformFetcher`, trust/secrets, generation
  data structures) so implementation has nothing left to invent.
- [`acceptance-criteria.md`](acceptance-criteria.md) — a **definition-of-done**
  (concrete check/assertion) for every implementation-plan item.
- [`known-issues.md`](known-issues.md) — the adversarial-review accounting and
  revision log. (F1/F2/F3 are now resolved in [`decisions.md`](decisions.md).)

## Problem

AOS today has two disjoint planes of host configuration that never resolve
against each other:

1. **Build-time module evaluation → image.** The NixOS-style module system
   (`lib/modules.nix`) is evaluated *on the builder*, producing
   `system.build.toplevel` (kernel, initrd, the composefs `/etc` overlay,
   systemd units). It is baked into the image and is immutable per image. Base
   config — networking, users, base services — can only change by rebuilding
   and reshipping an image.

2. **APM `expose` → flat per-package merge.** Each package ships RFC-0001
   `expose` metadata (units, `firewall.*`, `kernel.*`, config artifacts,
   permissions, credentials), rendered to JSON at build time and materialized
   on-host by a **flat, per-package Rust merge** (`config_artifact.rs`) with
   **no cross-package resolution** — a package cannot contribute to a shared
   option, react to another package via `mkIf`, or participate in priority
   merge.

The goal is a download-only package manager (binaries pre-compiled in APM
registries, like a Debian host fed by APT) that nonetheless supports
generation-based, atomically-switchable, rollback-able host configuration for
systemd and `/etc` — driven by **cloud user-data** (`host.nix`, authenticated
according to the selected trust mode) as
the primary source of host configuration. Neither plane delivers that: plane 1
requires rebuilds; plane 2 has no module system, no composition, no generations
of its own.

RFC-0011 unifies the two planes into **one on-host `evalModules`**, fed by the
operator's `host.nix` from cloud user-data, evaluating downloaded
config-only modules over pre-built binary closures — eval-only, no builds — and
producing content-addressed, atomically-switchable generations.

## Core model

Two-stage evaluation:

- **Stage 1 — build / publish (off-host, derivation-producing).** `pkgs/*.nix`
  build binaries exactly as today. Additionally, each package's `expose`
  graduates from a static JSON blob into a real **config-only Nix module**,
  shipped as source in a second **`config` output** alongside the binary `out`.
  The config module references its own and other packages' outputs as **plain
  store-path strings** recorded at build time — never as `mkDerivation`
  results.

- **Stage 2 — activation (on-host, eval-only, config-producing).** APM resolves
  the desired package set, then runs one `lib.evalModules` over (a) the **base
  module library shipped in the image**, (b) every resolved package's `config`
  module, and (c) the operator's leaf **`host.nix`** — delivered as **literal
  Nix in the cloud user-data** and fetched by the `aos metadata` agent (Ignition
  is removed; see [`provisioning.md`](provisioning.md)). The evaluation emits a
  pure-data **manifest** (`/etc` entries,
  rendered unit texts, networking files). APM **materializes** that manifest
  imperatively into a content-addressed generation and runs the *existing*
  atomic switch (`activate.sh.in`, `mount --move --beneath`).

The discipline that makes "deferred eval on-host" and "nothing is built on
host" coexist: Stage-2 modules hold store-path **strings**, not derivations.
Interpolating a store-path string adds string context (metadata) but triggers
**no instantiation and no realization** — confirmed and documented in
`crates/aos-doc/src/data/language.rs`. Every path the modules reference already
exists locally as a downloaded NAR. Eval is pure value computation; it never
builds.

```text
STAGE 1 (off-host, builds)                STAGE 2 (on-host, eval-only)
──────────────────────────                ───────────────────────────
pkgs/*.nix (mkDerivation)                 base lib (in measured image) ─┐
  ├─ out    : binary closure  ──NAR──►    config modules (downloaded)  ─┼─► evalModules ─► MANIFEST
  └─ config : config module   ──NAR──►    host.nix (literal-Nix user-data)┘  (pure, no I/O)   │
       (refs paths as strings)                                                                │
                                          APM materializes (mkfs.erofs /etc, symlinks) ◄──────┘
                                            └─► content-addressed config-generation
                                                  └─► activate.sh.in: mount --move --beneath (atomic)
```

## Invariants

1. **Nothing is built on-host.** No package compilation, no `configure`/`make`,
   no derivation realization, no import-from-derivation. Stage-2 modules
   reference pre-built store paths as strings. Materializing a manifest into an
   `/etc` overlay (`mkfs.erofs` of composefs metadata, symlink trees) is
   *activation*, not building — the same category as `systemd-tmpfiles`.

2. **All binaries are pre-compiled in APM registries.** The host downloads
   closures (binary `out` + `config`) via the existing realization-graph
   machinery; it never substitutes a build for a download.

3. **Cloud user-data is the primary source of host configuration, as literal
   Nix.** Operator intent arrives as a leaf `host.nix`, either carried verbatim
   or bound by an authenticated provisioning bundle, and participates in the same
   `evalModules` as base and package modules — at the *evaluation* layer. The
   operator never authors systemd units or files in a provisioning format;
   everything is Nix.

4. **Configuration is packed into nix-store-addressed generations** that switch
   atomically and roll back. A config-generation is `(image_gen_parent,
   manifest_hash)`; the manifest hash is the content-address of the eval output
   and is reproducible from its recorded, authenticated inputs.

5. **Eval is pure and deterministic given its recorded inputs.** `--pure-eval`
   blocks ambient impurity; host-varying data enters only through **two recorded
   inputs** — the operator's `host.nix` *and* the platform-supplied
   `host.facts.*` (hashed as `facts_hash` in the manifest `inputs` + attestation).
   Identical inputs ⇒ byte-identical manifest. This is simultaneously the
   determinism property fleet dedup relies on and the reproducibility property the
   trust model rests on. (`host.nix` is operator-*authored* and authenticated by
   the configured platform or signing policy; facts are
   *recorded-and-attested* — see
   [`trust-and-secrets.md`](trust-and-secrets.md).)

6. **No secret material in the value graph.** The manifest is content-addressed,
   world-readable, and may be logged or cached; secrets are referenced by
   **handle**, resolved at activation by systemd, never seen by the evaluator.
   TPM-sealed ciphertext is permitted; plaintext is forbidden by construction.

## Resolved decisions

| # | Decision | Resolution |
|---|----------|------------|
| D1 | Where stage-2 eval runs | **Post-switch-root, stage-2** (initrd cannot reference the evaluator/toplevel without the documented `initrd → toplevel → initrd` cycle; registry trust + DNS are stage-2 constructs). New `aos-eval.service`, `After=network-online.target`, `Before=aos-install-packages.service`. |
| D2 | Config distribution | A second **`config` output** per package; its **closure is its import graph** (store-path-string imports captured by `nix-store --dump` reference scanning). The hand-maintained `requires` edge list is **removed**. |
| D3 | Shared library wiring | The base lib is **injected** (`specialArgs`/`_module.args`), version-bound to the image generation — not imported per package. Package config modules are leaf `{ lib, config, ... }:` modules. |
| D4 | Namespacing | **Per-package roots** (`{pkg}.*`) plus **"system extension"** packages owning shared roots (`firewall.*`). Declaration ownership is structural for private roots (root = package name), and the locally-derived **system roots map** (built from the installed set's `owns_roots`) for shared roots. |
| D5 | Dependency inference | `provides` **derived** from options-only eval and kept as **per-package metadata** (never aggregated registry-wide); `requires` **discovered** by publish-time AST scan + an **error-driven resolve↔eval fixpoint** (the strict module system already throws naming the missing option), dispatched via `SystemRoots` (shared roots) + structural package-name convention (private roots). No hand-authored TOML edges, no registry-published index. |
| D6 | Generation model | **TWO axes (a tree, not a grid):** image-generation (measured UKI: kernel+initrd+base-lib+evaluator) × config-generation (manifest → `/etc` overlay). Config-gens are children of the image-gen they were evaluated against. |
| D7 | ABI binding | A monotonic integer **`module_abi`** baked into the image's `os-release`/toplevel; each config module declares a compat range; the resolver **fail-closed refuses** incompatible modules pre-eval (mirrors `trust_ctx.enforce_totality()` and the SBAT-generation precedent). |
| D8 | Merge precedence | **operator host.nix > package > defaults**, via reserved priority bands: host.nix bare defs = `mkOverride 75` (between `mkForce` 50 and normal 100), applied by **file-provenance priority tagging** at `modules.nix:695` — never subtree-wrapping. |
| D9 | Host facts | Enter **only** as typed config under a privileged-owned `host.facts.*` root (`attrsOf`-keyed-by-MAC name injection), never `specialArgs`. |
| D10 | Conflicts | Two **installed owners** of one shared root → hard error, **per-system** at resolve time (optionally early at install), citing both; the registry never adjudicates ownership. Shared scalars typed `uniq`/`mergeEqualOption` so equal-priority disagreement is a **loud error**, not silent last-wins. |
| D11 | Enablement & conscription | **Foreign conscription forbidden; provider enablement allowed.** A package may write/enable only within roots it **owns or is a registered provider/contributor of**; it may not enable a *foreign* service it merely depends on (`redis-exporter` cannot start `redis` — it declares a resolve-time assertion `redis.enable` that fails loudly). A registered provider may enable the sub-features it ships within its root (`nginx-full` setting `nginx.modules.http3.enable`). Top-level `{service}.enable` stays operator-owned in `host.nix` (installing ≠ starting; `apm install` injects the operator's enable); the operator always overrides (priority 75). Enforced at resolve time via per-def authenticated provenance + the installed owner's contributable surface in `SystemRoots`. |
| D16 | Variants & alternatives | A logical service (`nginx`) is a shared root; concrete variants (`nginx-full`, `nginx-minimal`, `nginx-light`) are mutually-exclusive **alternative providers** (`Provides`/`Conflicts` on the virtual root), so exactly one declares/implements `nginx.*` in any resolved set — single-declarer (D10) holds per-set. The operator selects by installing the variant and enables via `nginx.enable`. |
| D17 | Ignition removed; systemd-native substrate | Ignition is **removed**. Substrate is provisioned by **`systemd-repart`** (idempotent partition/grow — subsumes `aos-growfs`+`aos-gpt-relocate`), **`systemd-cryptenroll`/`cryptsetup`** (already RFC-0006's `/var` seal), `systemd-tmpfiles`, `systemd-sysusers`. The initrd validates a typed provisioning-bundle storage plan before rendering transient `repart.d`; when no plan is declared it uses the image-baked convention. Full `host.nix` evaluation remains in stage-2. See [`provisioning.md`](provisioning.md). |
| D18 | Idempotent vs one-shot lifecycle | **Prefer convergent tools** (repart/tmpfiles/sysusers/cryptsetup-attach — no guard, run every activation); **guard only genuinely-destructive ops** with a **state probe** (`cryptsetup isLuks`, `blkid \|\| mkfs`) preferred over a marker, `ConditionFirstBoot=` for identity ops; **never guard a convergent op**. A Nix module declares desired state; the materializer renders the correct guard — destructive → `Type=oneshot`+probe (outside reconcile), config → manifest `etc`+`units.action` (reconciled every activation). |
| D19 | Provisioning as a systemd unit graph | The eval emits `manifest.json` + `graph.json`; a compiler writes **per-package templated instance units** (`aos-pkg-fetch@<p>`/`aos-pkg-install@<p>`) + edge dropins into `/run/systemd/system`, `daemon-reload`s, and starts `aos-config.target`. APM fetch/render are units; the config DAG becomes systemd ordering. **`Wants=`** (not `Requires=`) pulls packages so a failure **degrades** (`is-system-running=degraded`, box reachable) rather than fails the boot; `Requires=`/`BindsTo=` reserved for true substrate edges (→ rescue/emergency). The single `activate.sh.in` `mount --move --beneath` stays the lone atomic commit. See [`orchestration.md`](orchestration.md). |
| D20 | Literal-Nix user-data; `aos metadata` agent | Cloud user-data is either literal `host.nix` or an `aos.provisioning/v1` bundle that binds `host.nix` bytes (inline or URL+SHA-256) and an optional typed storage plan. The **`aos metadata`** initrd agent owns cross-cloud acquisition. In the default `platform` mode, delivery by the selected metadata/config-drive channel authorizes the bundle. In `signed` mode, the exact bundle bytes are verified in initrd against public anchors included in the measured initrd **before any disk mutation**. The validated plan is rendered to transient `repart.d`; raw fragments are never accepted. The same authenticated host input survives switch-root for full stage-2 evaluation. Instance facts enter as `host.facts.*` (D9), not imperative writes. |
| D12 | Evaluator | **Stock C++ Nix for P1** (already packaged), sandboxed `--pure-eval --restrict-eval --allow-import-from-derivation=false` and bounded by a hardened transient systemd unit (`MemoryMax`/`RuntimeMaxSec`). **aos-nix for P2** behind the same seam. |
| D13 | Manifest trust | The locally-computed manifest needs **no signature**: it is a deterministic function of authenticated inputs and is fully re-derivable. Measure the *producer* (UKI), seal-protect the *product* (`/var`), attest the *input set*. |
| D14 | host.nix authenticity | Trust is policy-selected. The default **`platform`** mode trusts the cloud/deployment control plane that delivered user-data. The opt-in **`signed`** mode requires an SSHSIG-authenticated provisioning bundle (or detached signature for literal `host.nix`) against image-baked public anchors. Any signed-mode failure is fail-closed; a declared early storage plan is never applied unless its whole bundle has already been authorized. |
| D15 | Secrets | Referenced by **handle** via an opaque `secretRef` type + an activation-time resolution contract; backend/rotation/distribution **deferred** to the forthcoming secret-management system. |

## Open questions

These do not block the design; they are tuning decisions tracked in the topic
files.

1. **Config-gen retention vs image-gen retention.** Config-gens are cheap
   (`/var`, keep many); image-gens are expensive (ESP ×2 → 2 A/B slots).
   Re-eval of a config-gen across an ABI boundary needs that image-gen's
   base-lib retained. Decision: keep ≥1 prior base-lib on `/var` independent of
   ESP slot count, or accept re-download. See [`generations.md`](generations.md).
2. **Exact measured locus of `module_abi`.** Confirm the base-lib digest (hence
   the ABI) is inside the PCR-11-measured UKI section, so "ABI integrity for
   free" holds. See [`trust-and-secrets.md`](trust-and-secrets.md).
3. **`stateVersion` vs `module_abi`.** Two adjacent version axes
   (`aos.system.stateVersion` for state migration vs `module_abi` for option
   schema). Decide whether they collapse or stay orthogonal.
4. **Auto-reboot orchestration** for combined image+config upgrades — a
   reboot-spanning two-phase transaction vs a first-boot re-eval service (the
   latter is simpler and matches today's first-boot ignition rendering).
5. **host.nix revision pinning per config-gen**, so re-eval after an image
   rollback reproduces the config-gen's intended `host.nix`, not fork HEAD.

## Relationship to other RFCs

- **[RFC-0001](../0001-package-sandboxing/)** — `expose` is the embryo of the
  stage-2 config module; RFC-0011 evolves it from a flat JSON blob into an
  evaluated module and replaces the flat Rust merge.
- **[RFC-0003](../0003-install-from-image.md)** — the A/B image install/upgrade
  mechanism that the image-generation axis tracks.
- **[RFC-0005]** — the signed-tag → blessed realization graph that is the trust
  root for downloaded `config` closures (the narinfo itself is unauthenticated).
- **[RFC-0006](../0006-secure-boot/)** — measured/secure boot; RFC-0011 is
  congruent with it (measured = image-gen, derived/unmeasured = config-gen) and
  extends its attestation to the config-eval input set.
- **[RFC-0007](../0007-nix-evaluator/)** — `aos-nix`, the P2 evaluator and the
  source of richer graph intrinsics (exact read-tracing, in-engine bounding,
  incremental cache).
