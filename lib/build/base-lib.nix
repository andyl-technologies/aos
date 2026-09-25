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
##!   - `frozen-pkgs.json` — every package selected for this target from its
##!     native platform declaration, captured here at stage-1 (image build) via
##!     `freeze-pkgs.nix` in a reversible encoding that does not retain those
##!     packages in the image closure,
##!   - `frozen-artifacts.json` plus `artifact-roots/` symlinks — the stage-1
##!     store paths of image-fixed config artifacts, retained through ordinary
##!     Nix output references (`aos.config._artifactSources`),
##!   - `image-manifest.json` — the immutable image's rendered artifact
##!     baseline, with the base library output linked through Nix's output
##!     placeholder,
##!   - `system-modules.nix` — the variant's module list, and
##!   - `default.nix` (from `base-lib-entry.nix`) exporting `evalHostConfig`.
##!
##! `mkBaseLib` evaluates the real package set at image-build time to capture
##! `_artifactSources`, the option schema, and the image artifact baseline. The
##! candidate manifest is recomputed on-host under a frozen `pkgs`; the eval-only
##! core (the engine laziness fixes + the F2-A job-script inversion) is what
##! makes that recomputation build-graph-free and byte-identical to this
##! stage-1 manifest.
{
  lib,
  pkgs,
  system,
}: {
  ## The auto-discovered base module list (`import ./modules`).
  baseModules,
  ## The image variant's own module list (e.g. `[ ./systems/server.nix ]`).
  systemModules,
  ## Ephemeral repository-test modules included in the build-time baseline but
  ## deliberately excluded from the deployable replay source set.
  fixtureModules ? [],
  ## Authenticated operator modules participating in the image-build fixed point.
  operatorModules ? [],
  ## Generation-pinned runtime modules participating in the image-build fixed point.
  runtimeModules ? [],
  ## The ABI resolved from the image's complete module list, including inline
  ## image settings that cannot be copied into the source-backed library.
  moduleAbi,
  ## A short name for the variant, used only in the derivation name.
  systemName ? "system",
  ## Exact authenticated package modules selected for the host graph.
  hostPackageModules ? [],
  ## Stage-specific host modules selected by the image graph.
  hostConfigurationModules ? [],
  ## Exact authenticated provider modules selected by host bindings.
  hostProviderModules ? [],
  ## Resolver-produced host provider instances.
  hostAbilityInstances ? {},
  ## Exact source-composed host bindings.
  hostAbilityBindings ? {},
  ## Concrete host child requests retained across bounded resolution rounds.
  hostAbilityRequests ? {},
  ## Exact host child requirements retained across bounded resolution rounds.
  hostAbilityRequirements ? {},
  ## Typed host ability environment.
  hostAbilityEnvironment,
  ## Exact authenticated package modules selected for the initrd graph.
  initrdPackageModules ? [],
  ## Stage-specific initrd modules selected by the image graph.
  initrdConfigurationModules ? [],
  ## Exact authenticated provider modules selected by initrd bindings.
  initrdProviderModules ? [],
  ## Resolver-produced initrd provider instances.
  initrdAbilityInstances ? {},
  ## Exact source-composed initrd bindings.
  initrdAbilityBindings ? {},
  ## Concrete initrd child requests retained across bounded resolution rounds.
  initrdAbilityRequests ? {},
  ## Exact initrd child requirements retained across bounded resolution rounds.
  initrdAbilityRequirements ? {},
  ## Typed initrd ability environment.
  initrdAbilityEnvironment,
  ## Exact static contract projected by the complete initrd fixed point.
  initrdStaticAbilityContract,
  ## Option declarations from the converged host and initrd fixed points.
  hostOptionDeclarations,
  initrdOptionDeclarations,
}: let
  freeze = import ./freeze-pkgs.nix {inherit lib;};

  checkedHostPackageModules = lib.abilities.canonicalizeAuthenticatedModuleRecords hostPackageModules;
  checkedHostProviderModules = lib.abilities.canonicalizeAuthenticatedModuleRecords hostProviderModules;
  checkedInitrdPackageModules = lib.abilities.canonicalizeAuthenticatedModuleRecords initrdPackageModules;
  checkedInitrdProviderModules = lib.abilities.canonicalizeAuthenticatedModuleRecords initrdProviderModules;

  evaluationFor = {
    environment,
    packageModules,
    selectedProviderModules,
    abilityInstances,
    abilityBindings,
    abilityRequests,
    abilityRequirements,
    extraModules ? [],
    evaluationSpecialArgs ? {},
  }:
    lib.evalModules {
      modules =
        baseModules
        ++ systemModules
        ++ fixtureModules
        ++ [
          {aos.system.moduleAbi = lib.mkForce moduleAbi;}
          {aos.abilities.environment = environment;}
        ]
        ++ extraModules
        ++ lib.optional (abilityInstances != {} || abilityBindings != {}) {
          aos.abilities = {
            instances = abilityInstances;
            bindings = abilityBindings;
          };
        };
      inherit
        pkgs
        lib
        operatorModules
        runtimeModules
        packageModules
        selectedProviderModules
        ;
      enableAbilitySelection = true;
      specialArgs =
        {
          abilityResolution = {
            bindings = abilityBindings;
            requests = abilityRequests;
            requirements = abilityRequirements;
          };
        }
        // evaluationSpecialArgs;
    };

  checkedInitrdStaticContract = {
    identity = "${initrdStaticAbilityContract}/contract.json";
    path = "${initrdStaticAbilityContract}/contract.json";
  };

  initrdSchemaEval = evaluationFor {
    environment = initrdAbilityEnvironment;
    packageModules = checkedInitrdPackageModules;
    selectedProviderModules = checkedInitrdProviderModules;
    abilityInstances = initrdAbilityInstances;
    abilityBindings = initrdAbilityBindings;
    abilityRequests = initrdAbilityRequests;
    abilityRequirements = initrdAbilityRequirements;
    extraModules =
      initrdConfigurationModules
      ++ [
        {
          aos.config.evalAtBoot = {
            baseLib = baseLibOut;
            baseLibAbiHash = abiHash;
          };
        }
      ];
  };

  # The converged fixed points already carry the option declarations needed
  # for the ABI. Reusing them avoids another complete host module evaluation.
  # Check the final image evaluation below so conditional declarations cannot
  # silently change the schema after the ABI has been selected.
  schemaFor = declarations:
    builtins.sort (a: b: builtins.head a < builtins.head b) (
      lib.unique (
        builtins.map
        (decl: [decl.pathStr decl.typeSig])
        declarations
      )
    );
  optionSchema = schemaFor (hostOptionDeclarations ++ initrdOptionDeclarations);
  abiHash = "sha256:${builtins.hashString "sha256" (builtins.toJSON {
    abi = moduleAbi;
    schema = optionSchema;
  })}";

  # Capture the artifact baseline produced by the immutable image modules.
  # Nix replaces the output placeholder with this base library's final store
  # path while realizing the derivation, so the embedded manifest has the
  # exact same self-reference as later on-host evaluations.
  baseLibOut = builtins.placeholder "out";
  placeholderBaseLibDigest = builtins.hashString "sha256" baseLibOut;
  realEval = evaluationFor {
    environment = hostAbilityEnvironment;
    packageModules = checkedHostPackageModules;
    selectedProviderModules = checkedHostProviderModules;
    abilityInstances = hostAbilityInstances;
    abilityBindings = hostAbilityBindings;
    abilityRequests = hostAbilityRequests;
    abilityRequirements = hostAbilityRequirements;
    extraModules =
      hostConfigurationModules
      ++ [
        {
          aos.config.evalAtBoot = {
            baseLib = baseLibOut;
            baseLibAbiHash = abiHash;
          };
        }
      ];
    evaluationSpecialArgs = {
      initrdAbilityEvaluation = initrdSchemaEval;
      initrdStaticContract = checkedInitrdStaticContract;
    };
  };
  imageOptionSchema = schemaFor (realEval._optionDecls ++ initrdSchemaEval._optionDecls);
  optionSchemaMatchesImage =
    if optionSchema == imageOptionSchema
    then true
    else throw "base-lib: selected option schema differs from the complete image evaluation";

  # Root ownership shipped by the image is local system state, just like
  # package-owned roots derived from the exact installed profile. Every root
  # declared by the bundled base/system modules is already present and must
  # never trigger a structural package fetch. Extensible paths retain the
  # module engine's curated markers; interface ABI follows the image module ABI
  # until a root-specific image ABI is introduced.
  bundledRootNames = builtins.sort builtins.lessThan (lib.unique (
    builtins.map (declaration: builtins.head declaration.path) realEval._optionDecls
  ));
  bundledRoots =
    builtins.map (root: {
      inherit root;
      interface_abi = moduleAbi;
      extensible = builtins.sort builtins.lessThan (
        builtins.map
        (declaration: lib.concatStringsSep "." (builtins.tail declaration.path))
        (builtins.filter
          (declaration:
            declaration.extensible
            && builtins.head declaration.path == root
            && builtins.length declaration.path > 1)
          realEval._optionDecls)
      );
    })
    bundledRootNames;

  # logical-name -> stage-1 store path, for every registered (non-frozen)
  # artifact source. `"${drv}"` forces the artifact to its built path; context
  # is discarded so the JSON is a plain string map. The output also carries
  # one symlink per source below, preserving the same paths as real Nix output
  # references so every frozen artifact is present when the base lib is copied.
  frozenArtifactSourcesRaw = lib.filterAttrs (_: v: v != null) (
    realEval.config.aos.config._artifactSources
    // {
      # The static declaration inventory depends on the complete image
      # package set, so it cannot register through `_artifactSources`
      # without making that package set depend on its own artifact map.
      host-static-ability-contract = realEval.config.system.build.staticAbilityContract;
    }
  );
  invalidArtifactNames =
    builtins.filter
    (name: builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" name == null)
    (builtins.attrNames frozenArtifactSourcesRaw);
  frozenArtifactSources =
    if invalidArtifactNames == []
    then frozenArtifactSourcesRaw
    else
      throw
      "base-lib: config artifact names must be single safe path components; invalid: ${lib.concatStringsSep ", " invalidArtifactNames}";
  frozenArtifacts =
    builtins.mapAttrs (_: drv: builtins.unsafeDiscardStringContext "${drv}")
    frozenArtifactSources;

  frozenPkgsFile = builtins.toFile "frozen-pkgs.json" (freeze.freezeSelectedToJSON {
    packageSet = pkgs;
    packageNames = pkgs.packageNames;
  });
  frozenArtifactsFile = builtins.toFile "frozen-artifacts.json" (builtins.toJSON frozenArtifacts);
  plainJson = name: value:
    builtins.toFile name (builtins.unsafeDiscardStringContext (builtins.toJSON value));
  # Source-module roots remain ordinary store paths for the evaluator's
  # authenticated input loader. Output identities remain encoded until
  # selected for execution by the stage-specific runtime plan.
  frozenModuleRecords = records:
    builtins.map (record:
      (freeze.encodeStorePaths record)
      // {
        inherit (record) configRoot module;
      })
    records;
  initrdPackageModulesFile = plainJson "initrd-package-modules.json" (frozenModuleRecords checkedInitrdPackageModules);
  initrdProviderModulesFile = plainJson "initrd-provider-modules.json" (frozenModuleRecords checkedInitrdProviderModules);
  hostPackageModulesFile = plainJson "host-package-modules.json" (frozenModuleRecords checkedHostPackageModules);
  hostEvaluationInputsFile = plainJson "host-evaluation-inputs.json" {
    environment = hostAbilityEnvironment;
  };
  initrdEvaluationInputsFile = plainJson "initrd-evaluation-inputs.json" {
    environment = initrdAbilityEnvironment;
    abilityInstances = initrdAbilityInstances;
    abilityBindings = initrdAbilityBindings;
    abilityRequests = initrdAbilityRequests;
    abilityRequirements = initrdAbilityRequirements;
    staticContractIdentity = builtins.toString initrdStaticAbilityContract + "/contract.json";
  };
  # Module sources and the static contract are replay roots. Package outputs
  # are retained separately by the selected initrd runtime plan, so package
  # metadata alone cannot pull an unused CLI or toolchain into early boot.
  initrdAuthenticatedRoots = lib.unique (builtins.concatMap
    (record: [record.configRoot])
    (checkedInitrdPackageModules ++ checkedInitrdProviderModules)
    ++ [initrdStaticAbilityContract]);
  checkedInitrdAuthenticatedRoots =
    builtins.map
    (root:
      if builtins.getContext (builtins.toString root) == {}
      then throw "base-lib: frozen initrd authenticated root '${builtins.toString root}' has no retained store identity"
      else root)
    initrdAuthenticatedRoots;
  # Output identities are frozen without store context. Only module sources
  # must be retained here; selected runtime outputs have their own roots.
  hostModuleRoots = lib.unique (builtins.map (record: record.configRoot) checkedHostPackageModules);
  checkedHostAuthenticatedRoots =
    builtins.map
    (root:
      if builtins.getContext (builtins.toString root) == {}
      then throw "base-lib: frozen host authenticated root '${builtins.toString root}' has no retained store identity"
      else root)
    hostModuleRoots;
  hostStaticAbilityContract = realEval.config.system.build.staticAbilityContract;
  stageContractsDistinct =
    if builtins.toString hostStaticAbilityContract == builtins.toString initrdStaticAbilityContract
    then throw "base-lib: host and initrd fixed points must retain distinct static ability contracts"
    else true;
  rawImageManifest = realEval.config.system.build.configManifest;
  # Output placeholders acquire their real store-path context only when Nix
  # realizes this derivation. Add the self-reference explicitly so the
  # baseline's dependency inventory agrees with an on-host reevaluation.
  imageManifest = builtins.toJSON (rawImageManifest
    // {
      storePaths = lib.unique (rawImageManifest.storePaths ++ [baseLibOut]);
      ownership =
        rawImageManifest.ownership
        // {
          storePaths =
            rawImageManifest.ownership.storePaths
            // {"${baseLibOut}" = "@base";};
        };
    });

  # The image's source-backed module list, materialized as a Nix expression the
  # bundled entrypoint imports. Paths are rewritten to the corresponding
  # repository tree carried by the base library so they resolve under
  # `restrict-eval`.
  systemModulesNix = let
    rel = m: let
      s = builtins.toString m;
      bundledTrees = [
        {
          marker = "/lib/";
          prefix = "./lib/";
        }
        {
          marker = "/modules/";
          prefix = "./modules/";
        }
        {
          marker = "/pkgs/";
          prefix = "./pkgs/";
        }
        {
          marker = "/systems/";
          prefix = "./systems/";
        }
      ];
      matches =
        builtins.filter (
          tree: builtins.length (lib.splitString tree.marker s) > 1
        )
        bundledTrees;
    in
      if builtins.length matches == 1
      then let
        tree = builtins.head matches;
        parts = lib.splitString tree.marker s;
      in
        tree.prefix + builtins.elemAt parts 1
      else
        throw
        "base-lib: image module ${s} is not inside exactly one bundled repository tree";
  in
    "[\n"
    + lib.concatMapStringsSep "\n" (m: "  ${rel m}") systemModules
    + "\n  ./module-abi.nix"
    + "\n]\n";

  systemModulesFile = builtins.toFile "system-modules.nix" systemModulesNix;
  moduleAbiFile = builtins.toFile "module-abi.nix" ''
    {aos.system.moduleAbi = ${toString moduleAbi};}
  '';

  # Both image evaluation and source-stage transitions replay the same frozen
  # module inputs. The smaller view does not retain the image artifact baseline.
  copyEvaluationFiles = ''
    mkdir -p "$out"

    cp -rL --no-preserve=mode ${../../lib} "$out/lib"
    cp -rL --no-preserve=mode ${../../modules} "$out/modules"
    cp -rL --no-preserve=mode ${../../systems} "$out/systems"
    cp -rL --no-preserve=mode ${../../pkgs} "$out/pkgs"

    ${pkgs.sed}/bin/sed \
      -e "s|@system@|${system}|g" \
      -e "s|@abiHash@|${abiHash}|g" \
      ${./base-lib-entry.nix} > "$out/default.nix"
    cp ${frozenPkgsFile} "$out/frozen-pkgs.json"
    cp ${frozenArtifactsFile} "$out/frozen-artifacts.json"
    cp ${hostPackageModulesFile} "$out/host-package-modules.json"
    cp ${hostEvaluationInputsFile} "$out/host-evaluation-inputs.json"
    cp ${initrdPackageModulesFile} "$out/initrd-package-modules.json"
    cp ${initrdProviderModulesFile} "$out/initrd-provider-modules.json"
    cp ${initrdEvaluationInputsFile} "$out/initrd-evaluation-inputs.json"
    cp ${systemModulesFile} "$out/system-modules.nix"
    cp ${moduleAbiFile} "$out/module-abi.nix"

    mkdir -p "$out/initrd-authenticated-roots"
    ${lib.concatStringsSep "\n" (lib.imap (index: root: ''
        ln -s ${root} "$out/initrd-authenticated-roots/${toString index}"
      '')
      checkedInitrdAuthenticatedRoots)}
  '';

  initrdEvaluation = pkgs.runCommand "aos-initrd-evaluation-${systemName}" {} ''
    ${copyEvaluationFiles}
    mkdir -p "$out/host-module-roots"
    ${lib.concatStringsSep "\n" (lib.imap (index: root: ''
        ln -s ${root} "$out/host-module-roots/${toString index}"
      '')
      hostModuleRoots)}
  '';
in
  assert stageContractsDistinct;
  assert optionSchemaMatchesImage;
    pkgs.runCommand "aos-base-lib-${systemName}" {
      passthru = {inherit frozenArtifacts optionSchema moduleAbi abiHash initrdEvaluation;};
      inherit imageManifest placeholderBaseLibDigest;
      passAsFile = ["imageManifest"];
    } ''
      ${copyEvaluationFiles}
      mkdir -p "$out/host-authenticated-roots"
      ${lib.concatStringsSep "\n" (lib.imap (index: root: ''
          ln -s ${root} "$out/host-authenticated-roots/${toString index}"
        '')
        checkedHostAuthenticatedRoots)}
      mkdir -p "$out/artifact-roots"
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: artifact: ''
          ln -s ${artifact} "$out/artifact-roots/${name}"
        '')
        frozenArtifactSources)}
      actual_base_lib_digest=$(printf '%s' "$out" | ${pkgs.coreutils}/bin/sha256sum | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)
      ${pkgs.sed}/bin/sed \
        -e "s|sha256:$placeholderBaseLibDigest|sha256:$actual_base_lib_digest|g" \
        "$imageManifestPath" > "$out/image-manifest.json"
      echo ${lib.escapeShellArg systemName} > "$out/system-name"
      echo ${lib.escapeShellArg abiHash} > "$out/abi-hash"
      echo ${toString moduleAbi} > "$out/module-abi"
      cp ${builtins.toFile "option-schema.json" (builtins.toJSON optionSchema)} "$out/option-schema.json"
      cp ${builtins.toFile "system-roots.json" (builtins.toJSON bundledRoots)} "$out/system-roots.json"
    ''
