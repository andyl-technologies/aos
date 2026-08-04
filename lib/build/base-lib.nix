##! lib/build/base-lib.nix — assemble the in-image on-host eval-only base-lib
##!
##! Produces a self-contained derivation that the on-host
##! evaluator imports by store path to recompute the config manifest for a
##! verified `host.nix` WITHOUT touching the from-source build graph. The
##! derivation bundles:
##!
##!   - the AOS `lib`, `modules`, `systems`, and `pkgs` *source* trees (the
##!     module engine + every module definition; `pkgs` source is needed only
##!     for the handful of path literals modules reference — no package is
##!     built on-host),
##!   - `frozen-pkgs.json` — every package's already-built store path, captured
##!     here at stage-1 (image build) via `freeze-pkgs.nix`,
##!   - `frozen-artifacts.json` — the stage-1 store paths of the image-fixed
##!     config artifacts (`aos.config._artifactSources`),
##!   - `system-modules.nix` — the variant's module list, and
##!   - `default.nix` (from `base-lib-entry.nix`) exporting `evalHostConfig`.
##!
##! `mkBaseLib` runs the same real-`pkgs` `evalModules` the image build runs (so
##! it is shared, not extra work) purely to read back `_artifactSources`. The
##! manifest itself is recomputed on-host under a frozen `pkgs`; the eval-only
##! core (the engine laziness fixes + the F2-A job-script inversion) is what
##! makes that recomputation build-graph-free and byte-identical to this
##! stage-1 manifest. See `docs/rfcs/0011-on-host-config-eval/eval-only-core.md`.
{
  lib,
  pkgs,
  system,
}: {
  ## The auto-discovered base module list (`import ./modules`).
  baseModules,
  ## The image variant's own module list (e.g. `[ ./systems/server.nix ]`).
  systemModules,
  ## A short name for the variant, used only in the derivation name.
  systemName ? "system",
}: let
  freeze = import ./freeze-pkgs.nix {inherit lib;};

  # Same evaluation the image build performs — forced here only to read back
  # the registered image-fixed config artifacts.
  realEval = lib.evalModules {
    modules = baseModules ++ systemModules;
    inherit pkgs lib;
  };

  # logical-name -> stage-1 store path, for every registered (non-frozen)
  # artifact source. `"${drv}"` forces the artifact to its built path; context
  # is discarded so the JSON is a plain string map.
  frozenArtifacts =
    builtins.mapAttrs (_: drv: builtins.unsafeDiscardStringContext "${drv}")
    (lib.filterAttrs (_: v: v != null)
      realEval.config.aos.config._artifactSources);

  frozenPkgsFile = builtins.toFile "frozen-pkgs.json" (freeze.freezeToJSON pkgs);
  frozenArtifactsFile = builtins.toFile "frozen-artifacts.json" (builtins.toJSON frozenArtifacts);

  # The variant's module list, materialized as a Nix expression the bundled
  # entrypoint imports. Paths are rewritten to the bundled `./systems` copy so
  # they resolve inside the base-lib store path under `restrict-eval`.
  systemModulesNix = let
    rel = m: let
      s = builtins.toString m;
      # Keep only the `systems/...` tail so the path resolves under `$out`.
      parts = lib.splitString "/systems/" s;
    in
      if builtins.length parts > 1
      then "./systems/" + builtins.elemAt parts 1
      else throw "base-lib: system module ${s} is not under a systems/ directory";
  in
    "[\n"
    + lib.concatMapStringsSep "\n" (m: "  ${rel m}") systemModules
    + "\n]\n";

  systemModulesFile = builtins.toFile "system-modules.nix" systemModulesNix;
in
  pkgs.runCommand "aos-base-lib-${systemName}" {
    passthru = {inherit frozenArtifacts;};
  } ''
    mkdir -p "$out"

    # Bundle the source trees the on-host eval imports. `--no-preserve=mode` so
    # the copied files are writable enough for the store (the originals are
    # read-only store paths). Modules reference `../../pkgs/...` and
    # `../../lib/...` path literals, so all four trees must be present even
    # though no package is built.
    cp -rL --no-preserve=mode ${../../lib} "$out/lib"
    cp -rL --no-preserve=mode ${../../modules} "$out/modules"
    cp -rL --no-preserve=mode ${../../systems} "$out/systems"
    cp -rL --no-preserve=mode ${../../pkgs} "$out/pkgs"

    ${pkgs.sed}/bin/sed \
      -e "s|@system@|${system}|g" \
      ${./base-lib-entry.nix} > "$out/default.nix"
    cp ${frozenPkgsFile} "$out/frozen-pkgs.json"
    cp ${frozenArtifactsFile} "$out/frozen-artifacts.json"
    cp ${systemModulesFile} "$out/system-modules.nix"

    echo ${lib.escapeShellArg systemName} > "$out/system-name"
  ''
