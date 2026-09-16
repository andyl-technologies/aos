##! lib/build/oci/static-ability-contract.nix -- Static OCI ability contracts.
##!
##! This is the local orchestration boundary for symbolic package projections.
##! It binds each `(package, output)` selector through the caller's canonical
##! package registry, derives exact Nix artifact metadata, and then assembles the
##! realized platform contract. Container contracts preserve their existing
##! schema. Bootable host and initrd contracts add an explicit execution stage
##! so an artifact cannot claim that a later manager satisfies an early
##! consumer. Every form retains unresolved required bindings while carrying no
##! runtime grants.
{
  lib,
  mkDerivation,
  abilityContractValidator,
  common,
}: {
  platform ? null,
  targetPlatform ? null,
  packageRegistry ? null,
  packageRoots ? [],
  runtimeRoots ? [],
  contracts ? [],
  pname ? "aos-container-static-ability-contract",
  artifactClass ? "container",
  executionStage ? null,
}: let
  supportedArtifactClasses = ["container" "bootable"];
  supportedExecutionStages = ["initrd" "host"];
  schema =
    if artifactClass == "container"
    then "aos.container.static-abilities/v1"
    else "aos.boot.static-abilities/v1";
  mediaType =
    if artifactClass == "container"
    then "application/vnd.aos.container.static-abilities.v1+json"
    else "application/vnd.aos.boot.static-abilities.v1+json";
  contractPackageRoots =
    builtins.filter (
      package: builtins.isAttrs package && package ? contract
    )
    packageRoots;
  selectedPackages = map (package:
    if package ? contract
    then {
      payload = package;
      inherit (package) contract;
    }
    else common.fail "static ability contract package roots must expose one package contract")
  contractPackageRoots;
  payloadPaths = map (entry: builtins.toString entry.payload) selectedPackages;
  validPackageContract = contract:
    builtins.isAttrs contract
    && builtins.attrNames contract == ["document" "selectors" "value"]
    && builtins.isAttrs contract.document
    && contract.document ? outPath
    && builtins.isList contract.selectors
    && builtins.isAttrs contract.value
    && contract.selectors == contract.value.artifacts;
  resolvePackageOutput = payload: selector: let
    package =
      if selector.package == "self"
      then payload
      else if builtins.isAttrs packageRegistry && builtins.hasAttr selector.package packageRegistry
      then builtins.getAttr selector.package packageRegistry
      else common.fail "ability selector names unknown package '${selector.package}'";
    moduleOutput =
      if selector.output == "module" && package ? module
      then package.module
      else null;
    outputs = lib.unique ((package.outputs or ["out"]) ++ lib.optional (moduleOutput != null) "module");
  in
    if !(builtins.elem selector.output outputs)
    then common.fail "ability selector names missing output '${selector.output}' on package '${selector.package}'"
    else if moduleOutput != null
    then moduleOutput
    else if selector.output == "out"
    then package.out or package
    else builtins.getAttr selector.output package;
  contractPaths = map (contract: builtins.toString contract.artifact) contracts;
  platformMode = platform != null && contracts == [];
  combinedMode = platform == null && selectedPackages == [] && runtimeRoots == [] && contracts != [];
  checkedArtifactClass =
    if builtins.elem artifactClass supportedArtifactClasses
    then artifactClass
    else common.fail "static ability contract artifactClass must be container or bootable";
  checkedExecutionStage =
    if artifactClass == "container" && executionStage == null
    then null
    else if artifactClass == "bootable" && builtins.elem executionStage supportedExecutionStages
    then executionStage
    else common.fail "bootable static ability contracts require an initrd or host executionStage";
  checkedPlatform =
    if platformMode
    then common.validatePlatform platform
    else null;
  checkedTargetPlatform =
    if targetPlatform == null
    then
      if artifactClass == "container" || combinedMode
      then null
      else common.fail "bootable static ability contracts require an exact targetPlatform"
    else if
      builtins.isAttrs targetPlatform
      && builtins.attrNames targetPlatform == ["architecture" "system"]
      && builtins.isString targetPlatform.architecture
      && targetPlatform.architecture != ""
      && builtins.isString targetPlatform.system
      && targetPlatform.system != ""
    then targetPlatform
    else common.fail "static ability contract targetPlatform must contain exact system and architecture strings";
  checkedPackages =
    if !platformMode
    then []
    else if
      lib.all (entry:
        validPackageContract entry.contract
        && entry.contract.value.package.name == entry.payload.pname
        && entry.contract.value.package.version == entry.payload.version)
      selectedPackages
      && builtins.isAttrs packageRegistry
      && lib.all (path: builtins.elem path runtimeRootPaths) payloadPaths
      && builtins.length payloadPaths == builtins.length (lib.unique payloadPaths)
      && builtins.length selectedPackages
      == builtins.length (lib.unique (map (entry: builtins.toString entry.contract.document) selectedPackages))
    then selectedPackages
    else common.fail "static ability contract package roots must carry unique canonical contracts and runtime roots";
  packageResolutions = builtins.genList (packageIndex: let
    entry = builtins.elemAt selectedPackages packageIndex;
    selectorArtifacts = builtins.genList (selectorIndex: let
      selector = builtins.elemAt entry.contract.selectors selectorIndex;
      selected = resolvePackageOutput entry.payload selector;
    in {
      inherit (selector) package output;
      path = builtins.toString selected;
      graph = "abilityResolution${toString packageIndex}Selector${toString selectorIndex}";
      graphPath = selected;
    }) (builtins.length entry.contract.selectors);
  in {
    document = builtins.toString entry.contract.document;
    resolution = {
      payload = {
        path = builtins.toString entry.payload;
        graph = "abilityResolution${toString packageIndex}Payload";
      };
      source = {
        path = builtins.toString entry.payload.drvPath;
        graph = "abilityResolution${toString packageIndex}Source";
      };
      selectors = builtins.map (selected: builtins.removeAttrs selected ["graphPath"]) selectorArtifacts;
    };
    graphEntries =
      [
        {
          name = "abilityResolution${toString packageIndex}Payload";
          path = entry.payload;
        }
        {
          name = "abilityResolution${toString packageIndex}Source";
          path = entry.payload.drvPath;
        }
      ]
      ++ builtins.map (selected: {
        name = selected.graph;
        path = selected.graphPath;
      })
      selectorArtifacts;
  }) (builtins.length selectedPackages);
  resolvedPackageContracts = builtins.genList (packageIndex: let
    entry = builtins.elemAt selectedPackages packageIndex;
    resolution = builtins.elemAt packageResolutions packageIndex;
    resolutionSpec =
      builtins.toFile
      "${pname}-selector-resolution-${toString packageIndex}.json"
      (builtins.unsafeDiscardStringContext (builtins.toJSON resolution.resolution));
  in
    mkDerivation {
      pname = "${pname}-resolved-package-${toString packageIndex}";
      version = "1";
      src = null;
      buildDeps = [abilityContractValidator];
      exportReferencesGraph = builtins.listToAttrs (builtins.map (graphEntry: {
          name = graphEntry.name;
          value = [graphEntry.path];
        })
        resolution.graphEntries);
      phases = [
        {
          name = "resolve";
          script = ''
            ${abilityContractValidator}/bin/aos-ability-contract-validator \
              resolve-package-projection \
              ${lib.escapeShellArg (builtins.toString entry.contract.document)} \
              ${lib.escapeShellArg (builtins.toString resolutionSpec)} \
              "$NIX_ATTRS_JSON_FILE" \
              "$out"
          '';
        }
      ];
      outputChecks.out = {};
      preferLocalBuild = true;
      allowSubstitutes = false;
    }) (builtins.length selectedPackages);
  checkedContracts =
    if
      lib.all (contract:
        builtins.isAttrs contract
        && (contract._type or null) == "aos-oci-static-ability-contract"
        && builtins.isAttrs (contract.artifact or null)
        && contract.artifactClass == checkedArtifactClass
        && contract.executionStage == checkedExecutionStage)
      contracts
    then contractPaths
    else common.fail "static ability contract inputs must be produced by mkStaticAbilityContract";
  retainedPackageContractArtifacts =
    if platformMode
    then resolvedPackageContracts
    else lib.unique (lib.concatMap (contract: contract.retainedPackageContractArtifacts) contracts);
  runtimeRootPaths = map builtins.toString runtimeRoots;
  checkedRuntimeRoots =
    if
      platformMode
      && lib.all (root: builtins.isAttrs root && root ? outPath) runtimeRoots
      && builtins.length runtimeRootPaths == builtins.length (lib.unique runtimeRootPaths)
    then runtimeRoots
    else if combinedMode
    then []
    else common.fail "static ability contract runtimeRoots must contain unique derivations";
  validated =
    if platformMode || combinedMode
    then
      builtins.deepSeq [
        checkedArtifactClass
        checkedExecutionStage
        checkedPlatform
        checkedTargetPlatform
        checkedPackages
        checkedRuntimeRoots
        checkedContracts
      ]
      true
    else common.fail "static ability contract requires exactly one platform package set or a non-empty contract set";
  assemblyPackages = builtins.genList (index: {
    payload = builtins.toString (builtins.elemAt selectedPackages index).payload;
    manifest = builtins.toString (builtins.elemAt resolvedPackageContracts index);
  }) (builtins.length selectedPackages);
  assemblySpec =
    builtins.toFile
    "${pname}-static-ability-assembly.json"
    (builtins.unsafeDiscardStringContext (builtins.toJSON {
      inherit schema artifactClass executionStage;
      mediaType = mediaType;
      platform = checkedPlatform;
      targetPlatform = checkedTargetPlatform;
      packages = assemblyPackages;
      contracts = checkedContracts;
    }));
  contractArtifact = mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps =
      [abilityContractValidator]
      ++ retainedPackageContractArtifacts
      ++ map (contract: contract.artifact) contracts;
    exportReferencesGraph.staticAbilityRuntime = checkedRuntimeRoots;

    outputChecks.out = {};
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "assemble";
        script = ''
          ${abilityContractValidator}/bin/aos-ability-contract-validator \
            assemble-static-contract \
            ${lib.escapeShellArg (builtins.toString assemblySpec)} \
            "$NIX_ATTRS_JSON_FILE" \
            "$out"
        '';
      }
    ];

    meta.description = "Closed static ability contract for an AOS OCI artifact";
  };
in
  builtins.deepSeq validated {
    _type = "aos-oci-static-ability-contract";
    artifact = contractArtifact;
    inherit mediaType schema artifactClass executionStage checkedPlatform checkedTargetPlatform runtimeRootPaths;
    inherit retainedPackageContractArtifacts;
    inputContractPaths = contractPaths;
    selectedPayloadPaths = payloadPaths;
  }
