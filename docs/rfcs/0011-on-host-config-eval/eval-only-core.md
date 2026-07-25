# RFC-0011 — the eval-only core (design + validated mechanism)

Status: **the manifest is computable on-host, end-to-end, and validated**. A
full frozen-pkgs evaluation of the server `configManifest` runs under a `pkgs`
that has **no builder functions** and produces a manifest **byte-identical** to
the real-pkgs build-time manifest — while the build-side `system.build.toplevel`
stays **byte-for-byte identical** (same `.drv` hash). The remaining steps
(assemble `base-lib`, fix `stock.rs`, enable `evalAtBoot`, boot + fleet
validate) are integration, scoped in the roadmap below.

The earlier draft of this document predicted that an "eager-eval / mixed-module"
blocker would force a large render/assemble split of the mixed modules at the
*module* level. That turned out to be **unnecessary** — the real cause was two
laziness defects in the module engine plus a job-script representation issue,
all fixable far more surgically (see "What actually unblocked it" below).

## The problem

Stage-2 runs *on the host* under a sandbox (`restrict-eval`,
`allow-import-from-derivation=false`, a `MemoryMax`/`RuntimeMaxSec` cgroup). It
must evaluate the config modules + the operator `host.nix` into the manifest
(`config.system.build.configManifest`, a pure `aos.config-manifest/v1` attrset).

The naive approach — re-running the normal system eval on the host — does **not**
work, and this was never validated before now. Two failures, both reproduced:

1. **Sandbox config bug.** `crates/aos-package/src/config_eval/stock.rs` renders
   `import /nix/store/…-aos-base-lib` and ran evaluation with `--pure-eval`. Pure-eval
   **forbids importing any absolute path or `<search-path>`**, so it cannot even
   load base-lib. The correct sandbox is `restrict-eval` **without**
   `--pure-eval` (restrict-eval permits store paths + `-I` roots while still
   blocking arbitrary FS access; paired with no-IFD + the cgroup limits).

2. **Build-graph traversal (the hard one).** Under `restrict-eval` the import
   succeeds, but evaluating `configManifest` forces the store-path references in
   the rendered `/etc`/units, which forces the *from-source* `pkgs` derivations,
   which do **eval-time fetches** of the bootstrap chain (`stage0-posix`, …).
   `restrict-eval` forbids those URIs:

   ```text
   error: access to URI 'https://github.com/oriansj/stage0-posix/.../...tar.gz'
          is forbidden in restricted mode
   ```

   You cannot re-evaluate the whole from-source distro inside the host sandbox.

## Layer 1 — frozen pkgs (BUILT + VALIDATED)

`lib/build/freeze-pkgs.nix`. Every store path the manifest references already
exists in the image (built at stage-1). So freeze `pkgs`: replace each
derivation with a string-coercible record carrying its already-built
`outPath` (+ per-output paths) as **strings**, with `__toString` so
`${pkgs.foo}` / `${pkgs.foo.lib}` interpolate exactly as before — but with no
derivation behind them, so the eval never touches the build graph.

- `freezeToJSON pkgs` — stage-1 (base-lib build): forces the paths once,
  serialises `name → { path; outputs; outPaths; }`. (The JSON key is `path`, not
  `outPath`: `builtins.toJSON` coerces any `outPath`-bearing attrset to its path
  string, which would collapse the record.)
- `frozenFromJSON json` — stage-2: rebuilds the frozen set; touches no
  derivation.

**Validated on the builder:** `${frozen.bash}` equals real `bash`; multi-output
(`openssl.out`) resolves; frozen packages carry no `drvPath`. The module survey
confirms this is sufficient for the common case — modules use `pkgs` almost
entirely as bare `${pkgs.foo}` (no `.override`, essentially no multi-output or
`.meta` in the config path).

A frozen eval of the server `configManifest` runs and resolves frozen
store-path refs — confirming Layer 1 is sound — then stops at Layer 2.

## Layer 2 — image-fixed config artifacts (MECHANISM BUILT + VALIDATED)

`modules/base/config-artifacts.nix` implements the channel; `dbus.nix` is the
first conversion. **Validated on the builder:** existing systems stay
byte-identical (server toplevel `.drv` unchanged), and the frozen eval of the
server manifest now advances **past** `dbus-conf` to the next builder —
confirming the mechanism and that the frozen eval **converges** by converting
each manifest-path builder.

### The conversion pattern (per builder)

A module that builds an image-fixed artifact on the manifest path:

```nix
# let:  reference the resolved artifact, never the source.
dbusConf = config.aos.config.artifacts.dbus-system-conf;
# config:  register the source, GUARDED so the stage-2 frozen pkgs (which lacks
#          builder functions) never evaluates it.
aos.config._artifactSources.dbus-system-conf =
  if config.aos.config.frozenArtifacts ? "dbus-system-conf"
  then null
  else pkgs.dbus-conf { … };          # the original expression, unchanged
```

When `frozenArtifacts` is empty (every normal build) this resolves to the exact
same derivation → byte-identical. When the on-host evaluator injects the frozen
path, the `else` thunk is never evaluated, so the missing builder never errors.

### How few builders are actually on the manifest path

The fear was a *web* of interdependent image-fixed builders to convert one by
one. In practice, once the three engine/representation fixes above were in
place, a diagnostic frozen eval (frozen pkgs whose builder functions return a
recognizable `/STUB/<name>` sentinel) completed the whole manifest and showed
that **only three** builder outputs actually land on the server manifest path:

- `aos-prepare-ebpf-lsm-bpffs` (`modules/security/ebpf-lsm.nix`, `ExecStartPre`),
- `autologin-shell` (`modules/profiles/debug.nix`, agetty `--login-program`),
- `pam-limits` (`modules/base/pam.nix`, `pam_limits.so conf=`).

Every other builder in the module tree is toplevel-only and is never forced by
`configManifest`. The diagnostic-stub technique (run the eval, grep the manifest
JSON for `/STUB/`, the hits are exactly the builders to convert) is the fast way
to enumerate the manifest-path builders for any variant — far cheaper than a
slow per-builder eval loop.

### Three artifact classes

Each manifest-path builder falls into one of three classes:

1. **Image-fixed** — depends on *image* config, not `host.nix` (e.g. `dbus-conf`,
   the activate script, `packageSeedBundle`, `aos-prepare-ebpf-lsm-bpffs`,
   `autologin-shell`). → config-artifacts channel (freeze), byte-identical.
   **Converted + validated.**
2. **Config-dependent** — depends on `host.nix` (e.g. `etcBasedir`, which
   materialises octal-mode `/etc`). Must NOT be frozen — a frozen path would go
   stale the moment `host.nix` changes `/etc`. The manifest already carries these
   as **data** (octal `/etc` entries record `e.source`), so the artifact is
   redundant for stage-2 and must not be referenced there. `pam-limits` is the
   one currently treated as image-fixed-frozen (keyed by content hash); a
   `host.nix` limits override produces a new hash with no frozen artifact and
   fails loudly rather than serving stale limits — full config-dependence
   (rendering `limits.conf` as `/etc` data) is a tracked follow-up.
3. **Toplevel-only** — `kernel`, `initrd`, `toplevel`, `etcBasedir`/`etcDump`/
   `etcMetadataImage`, the per-unit `makeUnit` derivations, `systemdSystemUnits`.
   The manifest never needs them, and with the engine fixes above it never
   forces them.

### What actually unblocked it (no module split needed)

The frozen eval was forcing toplevel-only builders (`etcBasedir`, the per-unit
`makeUnit` derivations, …) even though `configManifest` does not reference them.
The cause was **not** that the engine is irreducibly eager — it was two specific
laziness defects plus one representation issue. Fixing them made forcing
`configManifest` touch only the data the manifest actually references, so a
mixed module like `build.nix` can keep defining both `configManifest` and
`toplevel` side by side.

1. **`config` folded in `allConfigMerged` (lib/modules.nix).** In the common
   (non-freeform, non-strict) case the engine built `config` as `deepMerge
   allConfigMerged finalConfig`. `allConfigMerged` is a structural merge of the
   *raw* module configs via `resolveIfs`, whose only effect on the result is to
   surface config at *undeclared* paths — which a well-formed module set never
   has. But building it forces every config leaf to WHNF (to resolve mkIf
   markers), including `system.build.etcBasedir = pkgs.runCommand …`. Fix:
   `config = finalConfig` in that case (each declared option already resolves
   its own mkIf/mkMerge via `collectDefsAtPath`). Result is identical for any
   all-declared config, and forcing one option no longer force-walks its
   siblings.

2. **mkIf-false defs forced in the `environment.etc` submodule
   (modules/base/build.nix).** `collectDefsAtPath` unwraps every mkIf def —
   *including condition-false ones* — and forces its `_value` to WHNF to check
   for nesting (it can't drop the dead branch without forcing the condition
   early, which creates fixpoint cycles). The submodule's `source = mkIf (text
   != null) "${textDrv}/…"` therefore built `writeTextFile` for every entry,
   even the many store-sourced ones whose `text` is null. Fix: an inner `text
   == null` guard so the dead branch is a plain string and WHNF never
   constructs the derivation. Byte-identical on the live branch.

3. **Job-script paths baked into eval-time unit text (F2-A inversion).** The
   `Exec*=` directives embedded the build-side job-script store path
   (`js.path = "${drv}/…"`), forcing the `writeTextFile` whenever a unit body
   was rendered — and the manifest reads every unit body. Fix: `Exec*=` now
   carries the drv-free `#aos-jobscript:<key>#` placeholder, and the *build-side*
   `makeUnit` substitutes placeholder→path when it materializes the unit file.
   So the eval-time unit text is drv-free (manifest renders it without forcing
   any job-script drv) while `systemd.build.systemdSystemUnits` stays
   byte-identical (`makeUnit` restores the real paths). A supporting fix: the
   `jobScripts` option is typed `listOf attrs` (freeform) rather than
   `listOf (attrsOf (either str package))`, whose per-field `package` check
   called `isDerivation` and forced `.drv` whenever the manifest read the
   string fields (`key`/`body`/`mode`).

With (1)–(3) plus the image-fixed builder conversions below, a strict
frozen-pkgs eval of the server `configManifest` completes and is byte-identical
to the real-pkgs manifest; the toplevel `.drv` is unchanged. The mixed modules
need no split.

## Layer 2 — original design notes

Some config modules **build a derivation at eval time** for a `/etc` artifact or
a unit input, e.g. `modules/services/dbus.nix`:

```nix
dbusConf = pkgs.dbus-conf { packages = cfg.packages; … };   # builds a derivation
# referenced in the unit ExecStart: --config-file=${dbusConf}/system.conf
```

`dbus-conf` is a *builder function*, not a top-level package, so Layer-1 freezing
skips it; the frozen eval fails `attribute 'dbus-conf' missing`. These artifacts
are **image-fixed** — they depend on *image* config (`cfg.packages`), not on the
operator `host.nix` — so they are identical across every config generation of a
given image.

Surface: ~15 module files call config-path builders (`runCommand`×12,
`writeTextFile`×6, `mkDerivation`×6, `writeShellScriptBin`×5, `dbus-conf`×3,
`stdenv`×1); only the subset whose output lands in `environment.etc` or a unit
body is on the manifest path. CS2 already did this for unit job-scripts (F2-A:
`manifest.jobScripts` carries text). The remaining artifacts get one of:

- **Render as text** when the content is a pure function of options (no file
  merging): emit the text inline into `environment.etc.<x>.text`, so the
  manifest carries bytes, not a store path.
- **Stage-1 freeze** when the artifact merges package files (like `dbus-conf`):
  build it once at stage-1, expose its store path to the stage-2 eval as a
  **frozen config artifact**. Mechanism: extend the frozen channel with an
  `artifacts` map (`logical-name → store-path`) computed at base-lib build time;
  the module reads the frozen artifact when present (stage-2) and builds it
  otherwise (stage-1). The key is image-fixity: the value does not vary with
  `host.nix`, so a single stage-1 computation is valid for every generation.

## base-lib assembly (roadmap)

`base-lib` is a stage-1 derivation containing:
- the config-only module subset + the wired `lib`,
- `frozen-pkgs.json` (Layer 1) + `frozen-artifacts.json` (Layer 2),
- a `default.nix` exporting `evalHostConfig { operatorModules, configModules }`
  = `evalModules { modules = baseModules ++ configModules; operatorModules;
  pkgs = frozenPkgs; lib; }`, exposing `config.system.build.manifest`
  (= `configManifest`; rename the option or alias it — and update `stock.rs` to
  read `configManifest` and drop `--pure-eval` for `restrict-eval`).

## Remaining steps to "complete RFC-0011"

1. ✅ Boot-path cutover: Ignition gated (byte-identical), new-path system builds.
2. ✅ Layer 1 frozen-pkgs: built + validated.
3. ✅ Layer 2: the manifest computes under strict frozen pkgs (no builder
   functions) and is **byte-identical** to the real-pkgs manifest. Required the
   three engine/representation fixes ("What actually unblocked it") plus the
   three image-fixed builder conversions; toplevel `.drv` unchanged. Validated
   on the builder, and green across `eval`, `system-characterization` (golden
   byte-diff), `module-enforcement`, `module-args`, `systemd-lib`,
   `systemd-generate`, `config-eval`, `config-parity`, `package-expose`,
   `package-preset`, `systemd-credentials`, `systemd-verity`, `lint`.
4. ✅ Build base-lib; fix `stock.rs` (sandbox + `configManifest`); prove a real
   on-host eval converges to a valid manifest under the sandbox.
   `lib/build/base-lib.nix` bundles the source + baked `frozen-pkgs.json` /
   `frozen-artifacts.json` and exports `evalHostConfig`. Validated on the
   builder: `evalHostConfig {}` and the exact `stock.rs` invocation (`nix-instantiate --store dummy:// --eval --strict --json
   --option restrict-eval true --option allow-import-from-derivation false
   -I <root> -I <base-lib> -A manifest entry.nix`) both produce a manifest
   byte-identical to the real-pkgs manifest. `stock.rs` drops `--pure-eval`,
   reads `configManifest`, and adds the imported store paths as `-I` roots.
   Remaining for step 5: wire `mkBaseLib` into the image build so
   `system.build` produces the variant's base-lib and `aos.config.evalAtBoot.
   baseLib` points at it.
5. ◐ Enable `aos.config.evalAtBoot` on `server-rfc0011` (✅ done) + boot validate
   (✅ done) + fleet validate (⏭ remaining). `server-rfc0011` builds with
   evalAtBoot on and its auto-wired base-lib, and **boots in a VM**:
   `nix-build -A systems.server-rfc0011.checks.system-boot` passes (erofs
   mounted, machine-id, neutral boot with Ignition off). A *fleet* test that
   delivers a `host.nix`, runs `aos-eval.service` to a manifest, and has
   `activate` apply the generation does not exist yet — it is the remaining
   runtime validation (today's `checks.config-eval` is eval/unit-level).
6. ⏭ Phase C removal — a multi-step migration, gated on step 5's fleet
   validation (Ignition is still the default backend, so it cannot simply be
   deleted):
   1. Flip the stock systems (`server.nix`, `edge`, …) to the new path
      (`ignition.enable = false`, `repart`/`metadata`/`evalAtBoot` on), or make
      `server-rfc0011` the canonical `server`. This changes those systems'
      toplevel bytes, so **regenerate the `system-characterization` golden**
      in the same reviewed diff.
   2. Boot-validate each migrated system.
   3. Delete `pkgs/boot/ignition.nix` + `pkgs/boot/butane.nix` (+
      `ignition-patches/`), `lib/formats/ignition.nix`, `lib/modules/ignition/`,
      and the ignition stage services in `modules/services/ignition.nix`
      (keeping the neutral-boot half). Retarget the ~20 consumer references
      (`aos-var-crypt`, `activate.sh.in`'s `@ignition@`, `config-seed.nix`,
      `secure-boot.nix`, the initrd `aos-platform-detect` `IGNITION_CONFIG_FILE`
      path, etc.) to the metadata/repart substrate.
   4. Migrate the tests: `modules/tests/ignition.nix`,
      `lib/testing/ignition-format.nix`, the `ignition-format` /
      `ignition-storage-files` checks, and the metadata-ISO helper
      (`lib/testing/metadata.nix` still serialises via the ignition format).
   5. Final gate: assert `pkgs.ignition` / `pkgs.butane` appear in **no** system
      closure.

   Surface: ~40 files reference `ignition`/`butane`; the core ignition files are
   ~1250 lines. This is a focused migration best done as a dedicated change with
   boot/fleet re-validation after each step, not folded into the eval-only core.

### Phase C is blocked on two unimplemented pieces (found by attempting it)

An end-to-end attempt at Phase C got far — the whole ladder validated on the
builder: flip Ignition off by default; `server` + `server-rfc0011` **boot** on
the new path; `apm upgrade --system` **succeeds** (after making `activate`'s
Ignition rendering conditional); `apm-install-at-boot` and `package-preset`
migrated to bake their intent into `/etc`; `pkgs.ignition` removed from **every**
system closure; the ~430-line stage-unit block + gate deleted. `checks.eval`,
`system-characterization` (golden regenerated), and the boot/upgrade VM tests
were all green.

Then `checks.fleet.install-from-image` **failed**: *"agent did not become ready
before manifest timeout"*. Root cause — two genuine gaps the removal exposed:

1. **The manifest materializer is unimplemented.** `aos-eval.service` writes
   `/run/aos/manifest.json` but nothing applies it: `activate` re-ran Ignition to
   render per-host `/etc`, and on the new path it simply leaves the per-gen lower
   empty (baked image `/etc` only). So a `host.nix` has **no runtime effect on
   either path** today — the RFC's own note ("a later changeset rewires
   consumption") is load-bearing. Applying `configManifest` (the artifact this
   document's eval-only core produces byte-identically) is the missing runtime
   half of RFC-0011.

2. **The fleet test harness delivers per-VM identity via Ignition.** Each fleet
   VM gets its `10-fleet-eth0.network` (its IP) and `/etc/ssh/authorized_keys/
   root` from an Ignition `storage.files` fragment on an `fw_cfg`/`instanceMetadata`
   channel, consumed by the in-image Ignition binary. Remove Ignition and
   image-boot VMs come up with no test network and no SSH key, so the driver
   can't reach them. (Agent-over-serial tests like `apm-system-upgrade` still
   pass, which is why the break only surfaced at `install-from-image`.) The
   new-path equivalent is per-VM identity delivered via the metadata agent +
   materializer (piece 1) — i.e. Phase C's fleet migration *depends on* the
   materializer.

Conclusion at the time of the attempt: full Ignition removal is gated on the
manifest materializer. The removal attempt was reset back out to keep the tree
fleet-green with the new path as a validated opt-in (`server-rfc0011`).

### Update: the materializer is now implemented (the block is on the fleet redesign)

The *consumer* half has since been built and validated, so a `host.nix` can now
take runtime effect:

- `crates/aos-package/src/config_eval/materialize.rs` + `apm __materialize
  --manifest <p> --etc-root <p>` applies a `configManifest`'s `/etc` tree
  (`text` entries with octal mode, relative install `symlink`s, absolute
  `store-symlink`s) and its job scripts (under `aos-job-scripts/<key>`) into a
  per-generation lower, rewriting `#aos-jobscript:<key>#` unit-body placeholders
  to their runtime paths. Idempotent.
- `activate` (`modules/base/activate.sh.in`) now selects the per-gen `/etc`
  backend by which source is present: Ignition fetch+files when
  `/run/ignition/platform.env` exists, else `apm __materialize` when
  `/run/aos/manifest.json` exists, else the baked image `/etc`. This also fixed
  a latent gap where the opt-in new path booted but `activate` (upgrade)
  hard-failed on the missing `platform.env`.
- Validated: 6 `materialize.rs` unit tests; `pkgs.aos` builds hermetically;
  `checks.config-materialize` feeds the **real** server `configManifest` to the
  **real** `apm __materialize` and asserts the applied `/etc` (text/mode,
  store-symlink into /nix/store, relative `.wants` link, job-script
  materialization + placeholder rewrite); `checks.fleet.apm-system-upgrade`
  (Ignition path) and `systems.server-rfc0011.checks.system-boot` (new path)
  both green.

So both halves of RFC-0011's core mechanism — the eval-only **producer** and the
materializer **consumer** — are now implemented and validated. What still gates
**full Ignition removal** is narrower: the *fleet test harness redesign*, plus a
booted-VM e2e. Those are integration/test-infrastructure work on top of the
now-existing runtime, not a missing runtime primitive.

### The fleet-harness redesign (the last mile to deleting Ignition)

`lib/testing/fleet.nix` delivers three things to each test VM through an
Ignition `storage.files` fragment consumed by the in-image Ignition binary:

1. **identity** — `/etc/hostname`, `/etc/hosts`, `/etc/systemd/network/
   10-fleet-eth0.network` (its static IP, matched by MAC);
2. **debug** (interactive mode) — `/etc/ssh/authorized_keys/root` (mode 0600)
   and a DHCP `.network` on the user-mode NIC;
3. **packages** — a `mkFleetPackageFragment` writing the desired-packages +
   registry files.

All three are plain `/etc` content, so none needs Ignition. The redesign, now
fully de-risked:

- Bake identity + debug directly onto each machine's system with the new
  `result.extendModules` (validated): `machineSystem = m.system.extendModules {
  modules = [ identityModule ]; }`, where `identityModule` sets the same paths
  via `environment.etc` (with `mode = "0600"` for the ssh key). Use
  `machineSystem`'s image instead of `m.system`'s + Ignition delivery.
- Route the package fragment through `aos.apm.installAtBoot`, whose desired.toml
  and registries already bake into `/etc` on the new path (the migration was
  proven in the reset Phase C attempt).
- Drop `composeIgnition`, `mkIgnitionConfig`/`mkMetadataIso`, the `fw_cfg`
  config.json, and the `varProvisioning = "ignition"` branch (no test sets it).
- Then execute Phase C removal (already validated on the builder up to
  `pkgs.ignition` gone from every closure) and **re-run the full fleet suite**
  (`install-from-image`, `apm-e2e`, `k3s-*`, `secure-boot*`, `measured-boot`,
  `apm-*`, …) — the slow, load-bearing validation, since this rewrites the
  harness every fleet test depends on.

This is a dedicated, high-blast-radius change to the core VM test infrastructure
(a prior rushed attempt broke `install-from-image`), so it is scoped as its own
reviewed change rather than folded in here. The runtime primitives it needs —
the materializer, `activate` wiring, and `extendModules` — are all in place and
validated.

**One more constraint the code review surfaced:** some fleet tests do not merely
*receive* config over Ignition — they *test Ignition itself*. `install-from-
image` (RFC-0003) delivers an `instanceMetadata` with `storage.disks` +
`storage.filesystems` and asserts that "ignition partitioned and formatted the
disk" (root-a/root-b/swap/var, the immutable-erofs-root + var-fills-disk
layout); `secure-boot`/`measured-boot` similarly exercise the Ignition disk
path. Removing Ignition removes those tests' *subject*, so they must be
**rewritten to validate the `systemd-repart` install flow** (the substrate
already exists and boots — `systems.server-rfc0011.checks.system-boot` is
green), not just re-plumbed for identity. That test-suite migration — not the
identity baking — is the substantive remainder of "remove all deprecated code,"
and it is deliberately not rushed: the runtime substrate is proven, but the
install/disk *assertions* are Ignition-shaped and need repart-shaped
replacements plus a full fleet re-run.
