# Generations: two axes, upgrade, rollback, ABI binding

This document specifies the relationship between **image generations** and
**config generations**, the upgrade and rollback ordering across both, and the
`module_abi` contract that binds them.

## Two axes, not one

Today there is one bundled generation axis: a `SystemGeneration { number,
toplevel, version, package_name, registry, created_at, kernel_path }` persisted
in `/var/lib/profiles/system/state.json` (`crates/aos-package/src/types.rs:3083-3112`),
whose `toplevel` carries kernel + initrd + base `/etc` + everything, switched as
one unit and applied with a `KernelUpgradeMode` (`sysroot.rs:78-90`).

RFC-0011 splits this into **two axes** — a tree, not a grid:

- **Image generation (substrate).** The measured, signed UKI = kernel + initrd +
  **base lib + evaluator** + render-core + baked trust anchors. Delivered as an
  A/B partition swap; tracked by the ESP `default aos-*.efi` glob
  (`modules/image/_builder.nix:176-183`), root-a/root-b, and the TPM PCR-11
  policy. Carries `module_abi`.
- **Config generation (overlay).** Pure data: a manifest → materialized `/etc`
  composefs overlay, produced by on-host eval, committed by the existing
  `current → gen-N` pointer switch via `activate.sh.in`. A config-gen is the
  pair `(image_gen_parent, manifest_hash)`.

**Config-generations are children of the image-generation they were evaluated
against.** Each image-gen `I` owns a lineage of config-gens evaluated against
`I`'s base lib.

### Why two

- **Different artifacts, transports, trust roots.** An image-gen is a measured,
  signed UKI delivered by A/B partition swap and is in the boot chain + TPM
  policy. A config-gen is unmeasured derived `/etc`, committed by a userspace
  pointer switch, explicitly *outside* the boot chain. Forcing them onto one
  axis means every `/etc` tweak reissues a measured boot artifact — exactly what
  RFC-0006's signed-policy design avoids.
- **Different cadence.** Image upgrades are rare, heavyweight, reboot-class (new
  kernel/initrd/base-lib/evaluator). Config changes are frequent, live, no-reboot
  (`mount --move --beneath`). One axis prices every config change at image cost.
- **The ABI seam only exists because the axes are separable.** "An image upgrade
  can change the base-lib ABI out from under downloaded config modules" *is* the
  coupling between the axes, modeled as a dependency edge from each config-gen to
  its image-gen's `module_abi`. You cannot reason about it on a single axis.

### Persisted shape

Split today's `SystemGeneration`:

- **Image-gen** keeps `{ kernel_path, uki/toplevel ref, version, module_abi,
  evaluator_ref }` — what A/B + UKI + `loader.conf` glob + TPM policy track.
- **Config-gen** (new, mirroring the existing `Profile`/`Generation` machinery
  in `crates/aos-package/src/profile/mod.rs`) holds `{ number, image_gen_parent,
  module_abi_pinned, manifest_hash, config_module_closure, host_nix_ref }`. The
  `current → gen-N` pointer `activate.sh.in` already commits becomes the
  **config-gen** pointer.

## Upgrade ordering when both change

Invariant: **the substrate that provides the base-lib/evaluator must be live
before the eval that targets it runs.** Therefore image-first, then re-eval,
then `/etc` switch — never eval on the source substrate (that would bind new
config modules to an ABI about to disappear). Composed with the existing flow:

1. **Stage the image-gen (offline, no activation).** APM downloads the new
   image-gen (UKI/toplevel), writes the new UKI into the ESP A/B slot alongside
   the old (`EFI/Linux/aos-<newver>.efi`; the `default aos-*.efi` glob selects
   it on next boot), records a *pending* image-gen. No config eval yet.
2. **Reboot into the new image-gen.** This is the kernel/base-lib/evaluator
   swap, reboot-class by nature. Measured boot: new PCR-11, signed policy
   unseals `/var` (RFC-0006, unchanged).
3. **First boot under the new image-gen triggers a full config re-eval.** The
   (now new) evaluator runs over: new base lib (in image) + downloaded config
   modules + the leaf `host.nix`. The **ABI gate** (below) fires here — any
   config module incompatible with the new `module_abi` is refused *before* a
   manifest is produced. Output: a new config-gen parented to the new image-gen.
4. **Materialize + atomic `/etc` switch via the existing path.** APM renders the
   manifest into a content-addressed gen dir and invokes `activate <N>` —
   overlay compose, pre-swap reconcile, `mount --move --beneath`, post-swap
   reconcile. Commit the config-gen pointer.

A **config-only change** (no image change) short-circuits to steps 3–4 — re-eval
against the *running* image-gen's base lib, then `activate`. No reboot. This is
the common case and stays cheap. Failure atomicity is already handled: an
ABI-gate failure in step 3 aborts before step 4 with the old config-gen live
(the `EX_PREPARE`/`EX_COMPOSE` "previous gen stays live" contract,
`activate.sh.in:161-214`); a failed new image in step 2 returns to the old UKI
slot via sd-boot.

## Rollback across both axes

Two independent verbs, because the axes are independent:

- **Config rollback (cheap, live, common):** a pointer switch among the
  config-gens *parented to the currently-running image-gen*. Pure
  `Profile::switch_to` + `activate <N>` — already implemented
  (`profile/mod.rs:282`, `rollback.rs`). No eval, no reboot. The per-gen `/etc`
  overlay uppers are already preserved across switch-away for exactly this
  (`activate.sh.in:325-348`).
- **Image rollback (reboot-class):** boot the other A/B UKI slot (old
  kernel/initrd/base-lib). A bootloader-level action, independent of APM's
  config pointer. **It is not "just boot the other slot" given the
  `default aos-*.efi` lexically-highest glob (review M-rollback-glob)** — that
  glob always re-selects the *newer/suspect* UKI on the next reboot. Durable
  image rollback must **`bootctl set-default` to the older UKI**, and new-image
  rollout should use **sd-boot boot-counting** (`aos-<ver>+3.efi` tries
  assessment) so a UKI that fails to boot is auto-demoted without operator
  action. The `default …glob` default is only the first-install fallback.

### The pinning rule

A config-gen is **pinned to the `module_abi` it was evaluated against** — not
blindly re-bindable to an arbitrary image-gen, because the manifest is the
*output* of evaluating config modules against a *specific* base-lib option
schema; replaying it against a different schema is undefined.

- **Re-activating a config-gen is valid iff its `module_abi_pinned` is
  compatible with the running image-gen's `module_abi`.** Same-ABI image upgrades
  (kernel/package change, no option-schema change — the common case) satisfy the
  pin, so a config-gen **freely re-activates across them**.
- **Different-ABI:** the old config-gen is **refused for direct activation**;
  instead the system **re-evals** `(old_base_lib, config_module_closure,
  host.nix)` — all three retained — to produce a *fresh* config-gen pinned to
  the rolled-back image-gen. Because eval is pure and content-addressed, this
  recomputation is deterministic and usually cache-hits.

### What must be retained

- **Per image-gen:** the UKI/toplevel (kernel+initrd+**base-lib**+evaluator) for
  as many A/B slots as kept (ESP is sized ×2 today,
  `modules/image/_builder.nix:192-197` → 2 image-gens). The base lib must be
  retained *with* its image-gen, because it *is* the ABI.
- **Per config-gen:** the materialized manifest/`/etc` gen dir **and** the eval
  inputs (`config_module_closure` + `host_nix_ref` + `module_abi_pinned` +
  `facts_hash`/`facts.json`). **These inputs must be GC-rooted, not just
  recorded (review M-gc-inputs):** the `cfg/` GC root pins manifest *outputs*
  (package runtime closures), which does **not** keep the config-module *source*
  NARs or `host.nix` alive — so a plain `apm gc` would break cross-ABI re-eval.
  A dedicated **`gen-N/cfgsrc/<hash>` root** pins the config-module source closure
  + the `host.nix` store path per config-gen (see
  [`operability.md`](operability.md)). Retaining inputs enables cross-ABI
  re-eval; retaining outputs makes same-ABI
  rollback a pointer switch.
- **`host.nix` lineage:** each config-gen records and GC-roots the exact
  content-addressed `host_nix_ref`, so re-eval after an image rollback
  reproduces the intended config rather than following a mutable source ref.

**Net:** a config-gen is pinned to its ABI, freely portable across image-gens of
the *same* ABI, and recomputable (never blindly replayed) across image-gens of
*different* ABI.

## ABI binding

A single monotonic integer **`module_abi`** versions the shared option schema
exported by the base lib. It is a property of the image-gen (the base lib lives
in the image), baked into the toplevel manifest / `os-release` (next to
`aos.system.version`, `modules/base/system.nix:124-141`) so the on-host resolver
reads the *running* image's ABI without trusting the network.

1. **Each image-gen declares `module_abi = K`.** Bump `K` only on a breaking
   change to a shared option (rename, removal, type change, or changed semantics
   of a rendered option). Additive options do not bump it.
2. **Each downloaded config module declares a compat range** `module_abi_compat
   = { min, max }`, analogous to how `SbatEntry` revocation floors gate UKIs by
   `(component, generation)` (`types.rs:3020-3024`).
3. **The resolver refuses any config module whose range excludes the running
   image's `K`** — *before* eval produces a manifest. Same shape as the existing
   `trust_ctx.enforce_totality()` gate (`sysroot.rs:192-204`): a hard, pre-eval,
   fail-closed check; the old config-gen stays live.
4. **The produced config-gen records `module_abi_pinned = K`**, which the
   rollback pin checks.

An integer (not semver) is correct here: the base lib is a single first-party
artifact shipped in the image, so a monotonic counter with an additive-vs-
breaking discipline is simpler to gate on than range arithmetic, and matches the
SBAT-generation precedent already in the codebase.

Per-package private roots (`{pkg}.*`) are **not** subject to `module_abi`: a
package's private option schema ships *with the package* and versions with it,
so there is no cross-package skew for private options. Only the shared base tree
needs the ABI contract — which is why the structural-core/extension split
(see [`module-system.md`](module-system.md)) keeps the ABI surface small. Each
fetched shared-root extension additionally carries its *own* interface ABI, so
interfaces evolve independently of the base.

## Resolved questions (see [`decisions.md`](decisions.md))

> All five are now locked in [`decisions.md`](decisions.md) (OQ): keep ≥1 prior
> base-lib via a dedicated per-image-gen GC root; `module_abi` measured via the
> UKI `.cmdline`; `stateVersion` and `module_abi` stay orthogonal; image+config
> upgrade uses a first-boot re-eval service (not a reboot-spanning transaction);
> each config-gen pins its `host_nix_ref`. Original framing kept for context.

1. **Retention depth mismatch.** Config-gens are cheap (`/var`, many);
   image-gens are expensive (ESP ×2 → 2 slots). Keeping config-gens parented to
   a GC'd image-gen loses the base lib needed to re-eval them across an ABI
   boundary. A dedicated GC root keeps at least one prior base lib on `/var`
   (just the lib, not the whole UKI) independently of the ESP slot count.
2. **Measured locus of `module_abi`.** The module ABI and base-lib digest are in
   the PCR-11-measured UKI `.osrel`; the dm-verity root hash in `.cmdline` binds
   the root bytes (see [`trust-and-secrets.md`](trust-and-secrets.md)).
3. **`stateVersion` vs `module_abi`.** `aos.system.stateVersion`
   (`system.nix:131`, state-migration trigger) and `module_abi` (option schema)
   are adjacent but distinct and remain orthogonal; a breaking option change
   often coincides with a state migration but not always.
4. **Auto-reboot orchestration.** With the base lib in the image, an image
   upgrade requires reboot before config can be evaluated. `apm upgrade`
   records pending intent; `aos-firstboot-reeval.service` performs the
   idempotent post-reboot re-evaluation without a reboot-spanning transaction.
5. **host.nix provenance per config-gen.** `host_nix_ref` is an exact content
   pin retained by the generation's `cfgsrc` GC root (see retention, above).
