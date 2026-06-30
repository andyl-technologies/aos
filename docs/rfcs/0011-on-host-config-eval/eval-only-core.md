# RFC-0011 — the eval-only core (design + validated mechanism)

Status: **partially implemented + validated**. The primary mechanism is built
and proven on the builder; the remaining layers are scoped below as a roadmap.

## The problem

Stage-2 runs *on the host* under a sandbox (`restrict-eval`,
`allow-import-from-derivation=false`, a `MemoryMax`/`RuntimeMaxSec` cgroup). It
must evaluate the config modules + the operator `host.nix` into the manifest
(`config.system.build.configManifest`, a pure `aos.config-manifest/v1` attrset).

The naive approach — re-running the normal system eval on the host — does **not**
work, and this was never validated before now. Two failures, both reproduced:

1. **Sandbox config bug.** `crates/aos-package/src/config_eval/stock.rs` renders
   `import /nix/store/…-aos-base-lib` and runs `nix eval --pure-eval`. Pure-eval
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

### Scope of the remaining grind

The frozen-eval loop converges by repeating the pattern. The surface is a *web*
of interdependent image-fixed artifacts, not just a flat file list — e.g.
`modules/packages.nix` alone has `packageSeedBundle` (`runCommand`),
`packageAttestationCatalog`, and per-package `metaFile` builders that reference
each other. Each manifest-path builder (`runCommand`×12, `writeTextFile`×6,
`mkDerivation`×6, `writeShellScriptBin`×5 [some already F2-A job-scripts],
`dbus-conf`×3) is converted the same way; toplevel-only builders are left alone
(the manifest never forces them). Run the cached-`frozen-pkgs.json` harness, fix
the reported builder, re-run, until `configManifest` serialises clean.

### Three artifact classes (learned from the grind)

Converting builders surfaced that they are not uniform — each manifest-path
builder falls into one of three classes, and only one is a "freeze":

1. **Image-fixed** — depends on *image* config, not `host.nix` (e.g. `dbus-conf`,
   the activate script, `packageSeedBundle`). → config-artifacts channel
   (freeze). **4 converted + validated.**
2. **Config-dependent** — depends on `host.nix` (e.g. `etcBasedir`, which
   materialises octal-mode `/etc`). Must NOT be frozen — a frozen path would go
   stale the moment `host.nix` changes `/etc`. The manifest already carries these
   as **data** (octal `/etc` entries record `e.source`), so the artifact is
   redundant for stage-2 and must not be referenced there.
3. **Toplevel-only** — `kernel`, `initrd`, `toplevel`, `etcBasedir` (for the
   gen-0 composefs). The manifest never needs them.

### The eager-eval / mixed-module problem (the real Layer-2 blocker)

The frozen eval forces `etcBasedir` even though `configManifest` does not
reference it — because **AOS's module system is eager**: evaluating
`config.system.build.configManifest` forces the whole `system.build` submodule,
which forces every sibling (`etcBasedir`, `kernel`, `initrd`, `toplevel`, …). So
the eval-only path cannot just "convert the builders" — it must **not define the
toplevel-only builders at all** in the stage-2 module set.

But `modules/base/build.nix` is a **mixed module**: it defines both
`configManifest` (config) and `toplevel`/`kernel`/`initrd`/`etcBasedir`
(toplevel). So base-lib's eval-only module set requires **splitting the mixed
modules** into a config-producing half (in base-lib) and a toplevel-producing
half (not in base-lib). This is the render/assemble split at the *module* level
— the substantial remaining design work, larger than the per-builder
conversions. Until it lands, the frozen-eval harness over-forces the toplevel
builders; the image-fixed conversions are still correct and byte-identical, but
full convergence needs the module split first.

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
3. ⏭ Layer 2: convert the ~15 manifest-path config-path builders (render-text or
   frozen-artifact). Loop the frozen eval until `configManifest` converges.
4. ⏭ Build base-lib; fix `stock.rs` (sandbox + `configManifest`); prove a real
   on-host eval converges to a valid manifest under the sandbox.
5. ⏭ Enable `aos.config.evalAtBoot` on `server-rfc0011`; boot + fleet validate
   (the metadata agent fetches `host.nix`, repart provisions, stage-2 eval +
   activate apply the config generation).
6. ⏭ Phase C removal: delete `pkgs.ignition`/`pkgs.butane`/`lib/formats/
   ignition.nix`, the ignition-specific units, retarget `aos-var-crypt`/
   `activate.sh.in`/the "read-only seed … via Ignition" message, migrate
   `modules/tests/ignition.nix` + the `ignition-format`/`ignition-storage-files`
   checks. The absence of `pkgs.ignition`/`butane` from every system closure is
   the final test.
