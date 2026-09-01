# RFC-0011: On-host, eval-only configuration — generations from downloaded Nix modules

- **Status:** **Implemented.** Accepted, revised after adversarial review, and
  completed against the executable acceptance gates. The three forks
  (F1/F2/F3) and the generations open
  questions are now **resolved** with locked choices + decision-free mechanisms
  ([`decisions.md`](decisions.md)); field-level interface/schema contracts are in
  [`build-spec.md`](build-spec.md); and every implementation-plan item has a
  definition-of-done in [`acceptance-criteria.md`](acceptance-criteria.md). F1 is
  resolved as **dm-verity on the erofs root with the roothash baked into the
  measured UKI `.cmdline`** (so PCR-11 transitively covers the evaluator +
  base-lib), reusing the existing `package-root-image.nix` verity recipe.
  The production path runs the hermetic AOS-built C++ Nix evaluator behind the
  `eval → manifest` seam. The experimental RFC-0007 evaluator was not accepted
  for production and remains recoverable from closed PR #104. The completed
  checklist lives in
  [`implementation-plan.md`](implementation-plan.md).
- **Date:** 2026-06-25
- **Audience:** anyone working on `lib/modules.nix`, `lib/types.nix`,
  `lib/modules/systemd/`, `modules/base/{build,apm,apm-registries,networking}.nix`,
  `modules/base/activate.sh.in`, `modules/services/aos-metadata.nix`,
  `modules/base/secure-boot.nix`, `crates/aos-package/`, `pkgs/tools/nix.nix`,
  `pkgs/build-support/_expose-renderer.nix`, or release/key operations.

This is a directory RFC. The README carries the status header, the core model,
the invariants, and the resolved decisions; the topic files hold the detail:

- [`architecture.md`](architecture.md) — the two-stage evaluation model, the
  render/assemble split that keeps "no build on host" honest, the `config`
  output, the manifest data contract, the stock evaluator, and
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
  restricted initrd evaluation of `aos.provisioning`, the one-time storage
  commit protocol, and the `aos metadata` transport/authentication agent.
- [`image-host-boundary.md`](image-host-boundary.md) — the rule that the golden
  image supplies capabilities and trust roots while `host.nix` supplies host
  policy, plus the migration of mixed profiles and artificial frozen artifacts.
- [`orchestration.md`](orchestration.md) — compiling the eval output into a
  systemd unit/target graph: runtime units in `/run/systemd/system`, templated
  per-package fetch/install instances, `Wants=`-driven degraded boot, the
  recovery ladder, and the single atomic-commit point.
- [`operability.md`](operability.md) — `apm switch --dry-run` + the off-host CI
  preflight, eval-failure observability, GC of config closures, the
  flat-merge ↔ module-eval parity gate, and the perf budget + test plan.
- [`runtime-module-sets.md`](runtime-module-sets.md) — composing a persistent,
  generation-pinned runtime module set over the independently authenticated
  cloud `host.nix`, including compatibility, transaction, and package-module
  rules.
- [`test-plan.md`](test-plan.md) — the structural-contract and behavioral test
  strategy: focused pure-eval assertions, manifest/materializer parity, fleet
  lifecycle coverage, and red-first subsystem test specs.
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

3. **Cloud user-data carries the sole host configuration, as literal Nix.**
   Operator intent arrives as a leaf `host.nix` and participates in the same
   `evalModules` as base and package modules. A size-limit pointer may locate
   and authenticate the exact file, but it cannot express configuration.
   There is no JSON storage plan or other parallel provisioning language.

4. **Configuration is packed into nix-store-addressed generations** that switch
   atomically and roll back. A config-generation is `(image_gen_parent,
   manifest_hash)`; the manifest hash is the content-address of the eval output
   and is reproducible from its recorded, authenticated inputs.

5. **Eval is restricted and deterministic given its recorded inputs.** The
   evaluator uses an eval-only dummy store, forbids IFD/builders, and permits
   imports only from explicit `-I` roots. Host-varying data enters only through
   **two recorded inputs** — the operator's `host.nix` *and* the platform-supplied
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
| D1 | Where evaluation runs | **Two closed projections of the same authenticated `host.nix`.** The initrd evaluates only `aos.provisioning` from the in-image base library; post-switch-root stage 2 performs the full resolve/eval fixpoint. The early projection has no package config modules, registry access, or `system.build` read, so it cannot form the full-evaluator closure cycle. |
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
| D17 | Ignition removed; `host.nix` provisions storage | Ignition is **removed**. The authenticated `host.nix` is partially evaluated in the initrd to a typed `aos.provisioning.storage` plan, independently validated in Rust, then applied through `systemd-repart` and the existing cryptsetup substrate. No raw repart text or second provisioning language is accepted. |
| D18 | Provision-once vs reconciliation | Disk topology is a one-time commit recorded by a reserved GPT provenance marker. A pending marker fails closed for explicit partial-commit recovery; only a committed operator/fallback label freezes automatic mutation. Metadata acquisition and full runtime evaluation still run every boot, with a hash-checked last-known-good fallback; a restricted dry-run reports storage drift without changing disks. Normal files, units, packages, networking, tmpfiles, sysusers, and unlock operations remain reconciled. |
| D19 | Provisioning as a systemd unit graph | The eval emits `manifest.json` + `graph.json`; a compiler writes **per-package templated instance units** (`aos-pkg-fetch@<p>`/`aos-pkg-install@<p>`) + edge dropins into `/run/systemd/system`, `daemon-reload`s, and starts `aos-config.target`. APM fetch/render are units; the config DAG becomes systemd ordering. **`Wants=`** (not `Requires=`) pulls packages so a failure **degrades** (`is-system-running=degraded`, box reachable) rather than fails the boot; `Requires=`/`BindsTo=` reserved for true substrate edges (→ rescue/emergency). The single `activate.sh.in` `mount --move --beneath` stays the lone atomic commit. See [`orchestration.md`](orchestration.md). |
| D20 | Literal-Nix user-data; `aos metadata` agent | Cloud user-data is literal `host.nix`. A minimal URL/SHA-256/signature pointer is permitted only as transport metadata for provider size limits. The **`aos metadata`** initrd agent owns cross-cloud acquisition and authenticates the exact Nix bytes under `platform` or `signed` policy before early evaluation. The same bytes survive switch-root for full stage-2 evaluation. Instance facts enter separately as recorded `host.facts.*`, not imperative writes. |
| D12 | Evaluator | **Stock C++ Nix** (already packaged), invoked as `nix-instantiate --store dummy:// --eval --strict --json --pure-eval` with every filesystem input admitted through a fixed-NAR-hash `fetchTree`, `restrict-eval`, and `allow-import-from-derivation=false`, then bounded by a hardened systemd unit (`MemoryMax`/`TimeoutStartSec`). |
| D13 | Manifest trust | The locally-computed manifest needs **no signature**: it is a deterministic function of authenticated inputs and is fully re-derivable. Measure the *producer* (UKI), seal-protect the *product* (`/var`), attest the *input set*. |
| D14 | host.nix authenticity | Trust is policy-selected. The default **`platform`** mode trusts the cloud/deployment control plane that delivered user-data. The opt-in **`signed`** mode requires an SSHSIG over the exact `host.nix` bytes against a measured vendor/fleet root or a key delegated by that root. `host.nix` cannot select its own trust policy or trust anchor. |
| D21 | Golden-image boundary | Consumers configure hosts through `host.nix`, not by rebuilding the release image. The image contains boot capabilities, evaluator/runtime mechanisms, bootstrap networking/storage, and initial trust roots. Roles, desired packages, identity, networking, users, services, runtime security and observability policy live in `host.nix`. Mixed profiles are split accordingly. |
| D15 | Secrets | Referenced by **handle** via an opaque `secretRef` type + an activation-time resolution contract; backend/rotation/distribution **deferred** to the forthcoming secret-management system. |

## Resolved operational decisions

The five former open questions are locked in
[`decisions.md`](decisions.md) and implemented as follows:

1. **Config-gen retention vs image-gen retention.** A dedicated base-lib GC
   root keeps at least one prior ABI closure on `/var`, independently of the two
   ESP A/B slots. Cross-ABI re-evaluation never relies on re-downloading it.
2. **Exact measured locus of `module_abi`.** `AOS_MODULE_ABI` and the base-lib
   digest are in the PCR-11-measured UKI `.osrel`; the dm-verity root hash in
   the measured `.cmdline` binds the actual erofs bytes.
3. **`stateVersion` vs `module_abi`.** The state-migration and module-schema
   axes remain orthogonal; neither implies a bump of the other.
4. **Auto-reboot orchestration.** Image upgrade records pending intent and the
   idempotent `aos-firstboot-reeval.service` performs post-reboot re-evaluation.
   There is no reboot-spanning transaction object.
5. **`host.nix` pinning per config-gen.** Each generation retains the exact
   content-addressed `host_nix_ref` through its `cfgsrc` GC root, so rollback
   re-evaluation cannot drift with a mutable source ref.

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
- **[PR #104](https://github.com/andyl-technologies/aos/pull/104)** — closed,
  unmerged experimental evaluator work retained for possible future recovery.
