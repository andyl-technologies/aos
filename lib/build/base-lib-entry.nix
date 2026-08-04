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
##!       packageModules  = [ { name = "pkg"; module = import <pkg>/module.nix; } … ];
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
  # The target system is frozen into the base library at image build time.
  # Stage 2 must not consult the evaluator host's ambient currentSystem.
  system = "@system@";

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
  # packages, which arrive at stage-2 as authenticated `packageModules`).
  baseModules = import ./modules;
  systemModules = import ./system-modules.nix;
in {
  inherit lib;

  ## Evaluate the closed one-time provisioning projection.
  ##
  ## This entrypoint is used in the initrd before package configuration modules
  ## or registry access exist. Only the provisioning schema module is declared,
  ## so unrelated `host.nix` definitions are dropped by the intentionally
  ## non-strict AOS module engine and are never forced.
  evalProvisioningConfig = {
    operatorModules ? [],
  }: let
    evaluated = lib.evalModules {
      # This closed projection has no package modules to arbitrate. Append the
      # operator module at the normal tier so attrsOf/submodule values merge
      # per key and field; the full evaluator retains the reserved priority-75
      # operator tier needed to beat package contributions.
      modules = [./modules/base/provisioning.nix] ++ operatorModules;
      pkgs = frozenPkgs;
      inherit lib;
    };
    partitions =
      builtins.mapAttrs
      (_: partition: {
        inherit
          (partition)
          device
          label
          type
          sizeMin
          sizeMax
          weight
          format
          uuid
          grow
          growFs
          priority
          ;
      })
      evaluated.config.aos.provisioning.storage.partitions;
  in {
    # Do not return the module engine's internal `_module` metadata. This
    # closed value is the complete initrd/Rust data contract.
    config.aos.provisioning.storage = {inherit partitions;};
  };

  ## Evaluate the package-name seed required before registry module resolution.
  evalHostSelection = {
    operatorModules ? [],
  }:
    lib.evalModules {
      modules = [./modules/base/host-selection.nix];
      pkgs = frozenPkgs;
      inherit lib operatorModules;
    };

  ## Evaluate a host configuration on-host into a config manifest.
  ##
  ## `operatorModules` is the verified leaf `host.nix` (CS4 operator-provenance
  ## seam — its bare defs win at the reserved priority-75 band). `packageModules`
  ## are resolver-owned `{ name; module; }` records for config-only outputs
  ## fetched from the registry. Returns
  ## the full `evalModules` result; the caller forces
  ## `config.system.build.configManifest`.
  evalHostConfig = {
    operatorModules ? [],
    packageModules ? [],
    factsModules ? [],
  }:
    lib.evalModules {
      modules =
        baseModules
        ++ systemModules
        ++ factsModules
        ++ [
          {
            aos.config.frozenArtifacts = frozenArtifacts;
            # Keep the full stage-2 projection self-referential: the generated
            # service must continue to name this exact ABI-pinned base library,
            # not the build-time default or an operator value.
            aos.config.evalAtBoot.baseLib = ./.;
          }
        ];
      pkgs = frozenPkgs;
      inherit lib operatorModules packageModules;
    };
}
