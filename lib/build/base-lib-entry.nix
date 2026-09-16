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
##!       authenticatedModules = [ (lib.authenticatedModule { … }) ];
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

  # Immutable artifact baseline used to distinguish image-owned output from
  # host changes to values that base modules project into aggregate files,
  # users, units, presets, and closure pins.
  imageManifest =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./image-manifest.json));

  # The bundled base module set + the image's system-variant modules. These are
  # exactly the modules the image was built from (minus the registry config
  # packages, whose authenticated wrappers enter the ordinary stage-2 module list).
  baseModules = import ./modules;
  systemModules = import ./system-modules.nix;

  projectAbilityRound = evaluated: manifest: let
    abilities = evaluated.config.aos.abilities;
    bindingNamesForRequest = requestName:
      builtins.filter
      (name: abilities.bindings.${name}.request == requestName)
      (builtins.attrNames abilities.bindings);
    authoredRequestKey = requestName: request: let
      prefix =
        if request.package == null
        then ""
        else "${request.package}:";
    in
      if prefix != "" && lib.hasPrefix prefix requestName
      then lib.removePrefix prefix requestName
      else throw "authored ability request '${requestName}' has no authenticated package-local key";
    unresolvedAuthoredRequests =
      lib.filterAttrs
      (name: _: bindingNamesForRequest name == [])
      abilities.requests;
    pendingAuthoredRequests =
      builtins.mapAttrs
      (name: request: {
        origin = "authored";
        request = name;
        identity = {
          consumer = abilities.instanceIdentities.${request.consumer};
          inherit (request) scope;
          key = authoredRequestKey name request;
        };
        declaration = request;
      })
      unresolvedAuthoredRequests;
    pendingProviderRequests =
      builtins.mapAttrs
      (_: request:
        request
        // {
          origin = "provider";
          identity = {
            consumer = abilities.instanceIdentities.${request.providerInstance};
            inherit (request.declaration) scope;
            key = request.localRequestKey;
          };
        })
      abilities.compositionPendingRequests;
    pendingRequests = pendingAuthoredRequests // pendingProviderRequests;
  in
    if pendingRequests == {}
    then {
      status = "complete";
      inherit manifest;
      fixedPoint = {
        inherit (abilities) bindings resolvedResources;
        executionObserver = abilities.resolvedExecutionObserver;
      };
    }
    else {
      status = "pending";
      pending = {
        requests = pendingRequests;
        requirements = abilities.compositionRequirements;
        providerInstances =
          builtins.mapAttrs
          (name: instance: {
            inherit (instance) implementation;
            identity = abilities.instanceIdentities.${name};
          })
          abilities.instances;
      };
    };
in {
  inherit lib imageManifest projectAbilityRound;

  ## Evaluate the closed one-time provisioning projection.
  ##
  ## This entrypoint is used in the initrd before package configuration modules
  ## or registry access exist. Only the provisioning schema module is declared,
  ## so unrelated `host.nix` definitions are dropped by the intentionally
  ## non-strict AOS module engine and are never forced.
  evalProvisioningConfig = {operatorModules ? []}: let
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
    runtimeModules ? [],
  }:
    lib.evalModules {
      modules = [./modules/base/host-selection.nix];
      pkgs = frozenPkgs;
      inherit lib operatorModules runtimeModules;
      enforceRuntimeDeclarations = false;
    };

  ## Evaluate a host configuration on-host into a config manifest.
  ##
  ## `operatorModules` is the verified leaf `host.nix` (CS4 operator-provenance
  ## seam — its bare defs win at the reserved priority-75 band).
  ## `authenticatedModules` are resolver-owned provenance wrappers imported
  ## through the ordinary module list. Returns
  ## the full `evalModules` result; the caller forces
  ## `config.system.build.configManifest`.
  evalHostConfig = {
    operatorModules ? [],
    runtimeModules ? [],
    authenticatedModules ? [],
    abilityBindings ? {},
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
            # Keep the full stage-2 projection self-referential. A path value
            # asks the evaluator to import this already-realized directory as
            # a new store object, yielding a nonexistent doubled-name path in
            # the manifest. Discarding the path context records the exact
            # immutable store path supplied via --base-lib instead.
            aos.config.evalAtBoot.baseLib =
              builtins.unsafeDiscardStringContext (builtins.toString ./.);
            aos.config.evalAtBoot.baseLibAbiHash = "@abiHash@";
          }
        ]
        ++ authenticatedModules;
      pkgs = frozenPkgs;
      inherit lib operatorModules;
      runtimeModules =
        runtimeModules
        ++ lib.optional (abilityBindings != {}) {
          aos.abilities.bindings = abilityBindings;
        };
    };

  ## Evaluates one build-stage ability graph without the host module surface.
  ##
  ## The caller supplies only a normalized data-only stage intent, authenticated
  ## package modules, checked provider selections, and their exact bindings.
  ## The returned module evaluation is projected through `projectAbilityRound`;
  ## no pending request is accepted by the build-stage adapter.
  evalAbilityStage = {
    stage,
    authority,
    key,
    intentModules ? [],
    authenticatedModules ? [],
    abilityBindings ? {},
  }:
    lib.evalModules {
      modules =
        [
          lib.abilities.module
          {
            aos.abilities.environment = {inherit authority key stage;};
          }
        ]
        ++ intentModules
        ++ authenticatedModules;
      pkgs = frozenPkgs;
      inherit lib;
      runtimeModules = lib.optional (abilityBindings != {}) {
        aos.abilities.bindings = abilityBindings;
      };
    };
}
