##! base-lib default.nix — generated on-host eval-only entrypoint
##!
##! This file is copied verbatim to `$out/default.nix` by
##! `lib/build/base-lib.nix`. It is the entrypoint the on-host stage-2
##! evaluator imports by store path (see
##! `crates/aos-package/src/config_eval/stock.rs`):
##!
##! ```text
##!   let
##!     baseLib = import <base-lib-store-path>;
##!     hostModule = import <verified-host.nix>;
##!     system = baseLib.evalHostConfig {
##!       operatorModules = [ hostModule ];
##!       configModules   = [ (import <pkg>/module.nix) … ];
##!     };
##!   in { manifest = system.config.system.build.configManifest; }
##! ```
##!
##! It re-assembles the AOS `lib` from the bundled `./lib` source, rebuilds a
##! *frozen* `pkgs` (string-coercible store paths, no derivations) from the
##! baked `./frozen-pkgs.json`, and evaluates the bundled base + variant module
##! set under that frozen `pkgs`. Because the manifest is build-graph-free by
##! construction (no builder functions are reachable — see
##! `lib/build/freeze-pkgs.nix`), the eval runs cleanly under the on-host
##! `restrict-eval` sandbox without touching the from-source build graph.
let
  # `import <base-lib>` returns this attrset directly (NOT a function), so the
  # on-host entry expression is simply `baseLib = import <store-path>;`. The
  # target system is read from `builtins.currentSystem` — correct on-host (the
  # box runs the image it was built for) and permitted under `restrict-eval`
  # (only `--pure-eval`, which this evaluator does not use, would forbid it).
  system = builtins.currentSystem;

  # `bash = null`: the on-host eval never invokes a builder (frozen pkgs), so
  # the derivation-building helpers in `lib` that would use bash are never
  # forced. Only the module engine + pure helpers are exercised.
  lib = import ./lib {
    inherit system;
    bash = null;
  };

  freeze = import ./lib/build/freeze-pkgs.nix {inherit lib;};

  # Frozen `pkgs`: every package is a string-coercible record carrying its
  # already-built store path. No derivation, so the eval never enters the
  # from-source build graph.
  frozenPkgs = freeze.frozenFromJSON (builtins.readFile ./frozen-pkgs.json);

  # Stage-1-captured store paths for image-fixed config artifacts
  # Layer 2). Injected as `aos.config.frozenArtifacts` so modules read the
  # frozen path instead of rebuilding (their builder functions are absent from
  # `frozenPkgs`).
  # `unsafeDiscardStringContext`: `readFile` of this store path adds context
  # that `fromJSON` rejects (see `freeze-pkgs.nix`).
  frozenArtifacts =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./frozen-artifacts.json));

  # The bundled base module set + the image's system-variant modules. These are
  # exactly the modules the image was built from (minus the registry config
  # packages, which arrive at stage-2 as `configModules`).
  baseModules = import ./modules;
  systemModules = import ./system-modules.nix;
in {
  inherit lib;

  ## Evaluate a host configuration on-host into a config manifest.
  ##
  ## `operatorModules` is the verified leaf `host.nix` (CS4 operator-provenance
  ## seam — its bare defs win at the reserved priority-75 band). `configModules`
  ## are the per-package config-only modules fetched from the registry. Returns
  ## the full `evalModules` result; the caller forces
  ## `config.system.build.configManifest`.
  evalHostConfig = {
    operatorModules ? [],
    configModules ? [],
  }:
    lib.evalModules {
      modules =
        baseModules
        ++ systemModules
        ++ configModules
        ++ [{aos.config.frozenArtifacts = frozenArtifacts;}];
      pkgs = frozenPkgs;
      inherit lib operatorModules;
    };
}
