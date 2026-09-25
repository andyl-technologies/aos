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
    abilityInterfaceDirectory = ./modules/abilities/_interfaces;
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
    if builtins.pathExists ./image-manifest.json
    then
      builtins.fromJSON
      (builtins.unsafeDiscardStringContext (builtins.readFile ./image-manifest.json))
    else throw "image manifest is unavailable in the initrd-only evaluation view";
  mergeImageManifestImpl = import ./lib/build/merge-image-manifest.nix {inherit lib;};

  # The bundled base module set + the image's system-variant modules. These are
  # exactly the modules the image was built from (minus the registry config
  # packages, which arrive at stage-2 as authenticated `packageModules`).
  baseModules = import ./modules;
  systemModules = import ./system-modules.nix;
  hostPackageModules =
    freeze.decodeStorePaths
    (builtins.fromJSON
      (builtins.unsafeDiscardStringContext (builtins.readFile ./host-package-modules.json)));
  frozenHostEvaluationInputs =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./host-evaluation-inputs.json));
  initrdPackageModules =
    freeze.decodeStorePaths
    (builtins.fromJSON
      (builtins.unsafeDiscardStringContext (builtins.readFile ./initrd-package-modules.json)));
  initrdProviderModules =
    freeze.decodeStorePaths
    (builtins.fromJSON
      (builtins.unsafeDiscardStringContext (builtins.readFile ./initrd-provider-modules.json)));
  frozenInitrdEvaluationInputs =
    builtins.fromJSON
    (builtins.unsafeDiscardStringContext (builtins.readFile ./initrd-evaluation-inputs.json));
  storeViewLib = import ./lib/build/store-view.nix {inherit lib;};

  baseLibraryModule = {
    aos.config.frozenArtifacts = frozenArtifacts;
    # Keep the full stage-2 projection self-referential. A path value asks the
    # evaluator to import this already-realized directory as a new store
    # object, yielding a nonexistent doubled-name path in the manifest.
    # Discarding the path context records the exact immutable store path
    # supplied via --base-lib instead.
    aos.config.evalAtBoot.baseLib =
      builtins.unsafeDiscardStringContext (builtins.toString ./.);
    aos.config.evalAtBoot.baseLibAbiHash = "@abiHash@";
  };

  # Replay the image constructor's package/stage selection pass. Stage
  # contributions are ordinary module values and may close over current
  # operator, runtime, fact, and package configuration. Derive them again from
  # those authoritative inputs instead of serializing a second representation
  # into the base library.
  evalConfigurationSelection = {
    operatorModules ? [],
    runtimeModules ? [],
    packageModules ? [],
    packageImportRoots ? {},
    factsModules ? [],
  }:
    lib.evalModules {
      modules = baseModules ++ systemModules ++ factsModules ++ [baseLibraryModule];
      pkgs = frozenPkgs;
      inherit lib operatorModules runtimeModules packageModules packageImportRoots;
    };
in rec {
  inherit lib imageManifest;
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
    packageImportRoots ? {},
    abilityInstances ? {},
    abilityBindings ? {},
    abilityRequests ? {},
    abilityRequirements ? {},
    abilitySelectionBindings ? abilityBindings,
    enableAbilitySelection ? true,
    factsModules ? [],
    configurationModules ? [],
  }:
    lib.evalModules {
      modules =
        baseModules
        ++ systemModules
        ++ factsModules
        ++ [baseLibraryModule]
        ++ configurationModules
        ++ lib.optional (environment != null) {
          aos.abilities.environment = environment;
        }
        ++ lib.optional (abilityInstances != {} || abilityBindings != {}) {
          aos.abilities = {
            instances = abilityInstances;
            bindings = abilityBindings;
          };
        };
      pkgs = frozenPkgs;
      inherit lib operatorModules packageModules selectedProviderModules packageImportRoots;
      inherit enableAbilitySelection;
      inherit runtimeModules;
      specialArgs.abilityResolution = {
        bindings = abilitySelectionBindings;
        requests = abilityRequests;
        requirements = abilityRequirements;
      };
    };

  ## Resolves selected provider modules around the complete host module graph.
  resolveHostConfig = {
    operatorModules ? [],
    runtimeModules ? [],
    packageModules ? [],
    factsModules ? [],
  }: let
    dynamicNames = builtins.listToAttrs (builtins.map (record: {
        name = record.name;
        value = true;
      })
      packageModules);
    imageModules =
      builtins.filter
      (record: !(builtins.hasAttr record.name dynamicNames))
      hostPackageModules;
    initialPackageModules = imageModules ++ packageModules;
    selectionEvaluation = evalConfigurationSelection {
      inherit operatorModules runtimeModules factsModules;
      packageModules = initialPackageModules;
    };
    configurationModules = selectionEvaluation.config.aos.abilities.stages.host.modules;
    resolution = import ./lib/build/resolve-ability-configuration.nix {
      inherit lib initialPackageModules;
      evaluate = {
        packageModules,
        providerModules,
        selectionModule,
        enableAbilitySelection,
        selectionBindings,
      }:
        evalCompleteConfig {
          environment = frozenHostEvaluationInputs.environment;
          inherit operatorModules runtimeModules packageModules factsModules;
          inherit configurationModules;
          selectedProviderModules = providerModules;
          abilityInstances = selectionModule.module.aos.abilities.instances;
          abilityBindings = selectionModule.module.aos.abilities.bindings;
          abilitySelectionBindings = selectionBindings;
          abilityRequests = selectionModule.requests;
          abilityRequirements = selectionModule.requirements;
          inherit enableAbilitySelection;
        };
    };
  in
    builtins.seq resolution.checked resolution.evaluation;

  ## Maps the frozen canonical initrd inputs into one checked read view.
  initrdEvaluationInputs = storeView: let
    checked = storeViewLib.validate storeView;
    staticContractIdentity = frozenInitrdEvaluationInputs.staticContractIdentity;
    staticContract = storeViewLib.staticContractFor checked staticContractIdentity;
  in {
    environment = frozenInitrdEvaluationInputs.environment;
    abilityInstances = frozenInitrdEvaluationInputs.abilityInstances;
    abilityBindings = frozenInitrdEvaluationInputs.abilityBindings;
    abilityRequests = frozenInitrdEvaluationInputs.abilityRequests;
    abilityRequirements = frozenInitrdEvaluationInputs.abilityRequirements;
    packageModules = builtins.map (storeViewLib.mapAuthenticatedModule checked) initrdPackageModules;
    selectedProviderModules = builtins.map (storeViewLib.mapAuthenticatedModule checked) initrdProviderModules;
    inherit staticContract;
  };

  ## Evaluates the frozen initrd through the same complete configuration graph.
  evalCompleteInitrdConfig = {
    storeView,
    sourceModuleRoots ? {},
    packageImportRoots ? {},
    operatorModules ? [],
    runtimeModules ? [],
    factsModules ? [],
    configurationModules ? [],
  }: let
    frozen = initrdEvaluationInputs storeView;
    contextualize = storeViewLib.contextualizeModule sourceModuleRoots;
    selectionEvaluation = evalConfigurationSelection {
      inherit operatorModules runtimeModules factsModules;
      inherit packageImportRoots;
      packageModules = builtins.map contextualize hostPackageModules;
    };
    stageConfigurationModules = selectionEvaluation.config.aos.abilities.stages.initrd.modules;
    evaluated = evalCompleteConfig {
      inherit operatorModules runtimeModules factsModules;
      inherit packageImportRoots;
      configurationModules = stageConfigurationModules ++ configurationModules;
      inherit (frozen) environment abilityInstances abilityBindings abilityRequests abilityRequirements;
      packageModules = builtins.map contextualize frozen.packageModules;
      selectedProviderModules = builtins.map contextualize frozen.selectedProviderModules;
    };
  in
    evaluated // {initrdStaticContract = frozen.staticContract;};

  ## Evaluates a host configuration through the common complete graph.
  evalHostConfig = {
    operatorModules ? [],
    runtimeModules ? [],
    packageModules ? [],
    factsModules ? [],
  }:
    resolveHostConfig {
      inherit operatorModules runtimeModules packageModules factsModules;
    };
}
