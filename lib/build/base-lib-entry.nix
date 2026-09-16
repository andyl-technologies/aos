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

  # Immutable artifact baseline used to distinguish image-owned output from
  # host changes to values that base modules project into aggregate files,
  # users, units, presets, and closure pins.
  imageManifest =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./image-manifest.json));
  mergeImageManifestImpl = import ./lib/build/merge-image-manifest.nix {inherit lib;};

  # The bundled base module set + the image's system-variant modules. These are
  # exactly the modules the image was built from (minus the registry config
  # packages, which arrive at stage-2 as authenticated `packageModules`).
  baseModules = import ./modules;
  systemModules = import ./system-modules.nix;
  initrdPackageModules =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./initrd-package-modules.json));
  initrdProviderModules =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./initrd-provider-modules.json));
  frozenInitrdEvaluationInputs =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./initrd-evaluation-inputs.json));
  storeViewLib = import ./lib/build/store-view.nix {inherit lib;};

  projectAbilityRound = evaluated: manifest: let
    abilities = evaluated.config.aos.abilities;
    bindingNamesForRequest = requestName:
      builtins.filter
      (name: abilities.bindings.${name}.request == requestName)
      (builtins.attrNames abilities.bindings);
    unresolvedAuthoredRequests = lib.filterAttrs
      (name: _: bindingNamesForRequest name == [])
      abilities.requests;
    pendingAuthoredRequests = builtins.mapAttrs
      (name: request: {
        origin = "authored";
        request = name;
        identity = {
          consumer = abilities.instanceIdentities.${request.consumer};
          inherit (request) scope;
          key = request.localKey;
        };
        declaration = request;
      })
      unresolvedAuthoredRequests;
    pendingProviderRequests = builtins.mapAttrs
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
        providerInstances = builtins.mapAttrs
          (name: instance: {
            inherit (instance) implementation;
            identity = abilities.instanceIdentities.${name};
          })
          abilities.instances;
      };
    };
in rec {
  inherit lib imageManifest projectAbilityRound;
  inherit (storeViewLib) readPathFor;

  ## Merge an evaluated runtime candidate with the immutable image baseline.
  mergeImageManifest = {
    baseline,
    candidate,
  }:
    mergeImageManifestImpl {inherit imageManifest baseline candidate;};

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

  ## Evaluates one complete authenticated configuration fixed point.
  ##
  ## `operatorModules` is the verified leaf `host.nix` (CS4 operator-provenance
  ## seam — its bare defs win at the reserved priority-75 band). `packageModules`
  ## are resolver-owned `{ name; module; }` records for config-only outputs
  ## fetched from the registry. Returns
  ## the full `evalModules` result; the caller forces
  ## `config.system.build.configManifest`.
  evalCompleteConfig = {
    environment ? null,
    operatorModules ? [],
    runtimeModules ? [],
    packageModules ? [],
    selectedProviderModules ? [],
    abilityBindings ? {},
    factsModules ? [],
    configurationModules ? [],
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
        ++ configurationModules
        ++ lib.optional (environment != null) {
          aos.abilities.environment = environment;
        };
      pkgs = frozenPkgs;
      inherit lib operatorModules packageModules selectedProviderModules;
      enableAbilitySelection = true;
      runtimeModules =
        runtimeModules
        ++ lib.optional (abilityBindings != {}) {
          aos.abilities.bindings = abilityBindings;
        };
    };

  ## Maps the frozen canonical initrd inputs into one checked read view.
  initrdEvaluationInputs = storeView: let
    checked = storeViewLib.validate storeView;
    staticContractIdentity = frozenInitrdEvaluationInputs.staticContractIdentity;
    staticContract = storeViewLib.staticContractFor checked staticContractIdentity;
  in
    {
      environment = frozenInitrdEvaluationInputs.environment;
      abilityBindings = frozenInitrdEvaluationInputs.abilityBindings;
      packageModules = builtins.map (storeViewLib.mapAuthenticatedModule checked) initrdPackageModules;
      selectedProviderModules = builtins.map (storeViewLib.mapAuthenticatedModule checked) initrdProviderModules;
      inherit staticContract;
    };

  ## Evaluates the frozen initrd through the same complete configuration graph.
  evalCompleteInitrdConfig = {
    storeView,
    operatorModules ? [],
    runtimeModules ? [],
    factsModules ? [],
    configurationModules ? [],
  }: let
    frozen = initrdEvaluationInputs storeView;
    evaluated = evalCompleteConfig {
      inherit operatorModules runtimeModules factsModules configurationModules;
      inherit (frozen) environment abilityBindings packageModules selectedProviderModules;
    };
  in
    evaluated // {initrdStaticContract = frozen.staticContract;};

  ## Evaluates a host configuration through the common complete graph.
  evalHostConfig = {
    operatorModules ? [],
    runtimeModules ? [],
    packageModules ? [],
    selectedProviderModules ? [],
    abilityBindings ? {},
    factsModules ? [],
  }:
    evalCompleteConfig {
      inherit
        operatorModules
        runtimeModules
        packageModules
        selectedProviderModules
        abilityBindings
        factsModules
        ;
    };
}
