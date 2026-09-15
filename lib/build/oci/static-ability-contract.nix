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
  packageRegistry ? null,
  packageRoots ? null,
  packages ? [],
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
  selectedPackages =
    if packageRoots == null
    then packages
    else
      map (package: {
        payload = package;
        manifest = package.abilities.projection;
      })
      (builtins.filter (
          package:
            builtins.isAttrs package
            && package ? abilities
            && package.abilities ? projection
        )
        packageRoots);
  packagePaths =
    map (entry: {
      payload = builtins.toString entry.payload;
      manifest = builtins.toString entry.manifest.document;
    })
    selectedPackages;
  validInterfaceProjection = interface:
    builtins.isAttrs interface
    && interface ? descriptor
    && interface ? document
    && interface ? value
    && builtins.isString interface.descriptor
    && builtins.isString interface.document
    && builtins.isAttrs interface.value;
  validPackageProjection = projection:
    builtins.isAttrs projection
    && projection ? document
    && projection ? interfaces
    && projection ? value
    && builtins.isString projection.document
    && builtins.isList projection.interfaces
    && builtins.isAttrs projection.value
    && builtins.isAttrs (projection.value.interfaces or null)
    && builtins.isAttrs (projection.value.guarantees or null)
    && lib.all validInterfaceProjection projection.interfaces
    && builtins.isList (projection.value.artifacts or null)
    && builtins.isList (projection.value.interface_documents or null)
    && builtins.length projection.interfaces
    == builtins.length projection.value.interface_documents
    && lib.all (index: let
      retained = builtins.elemAt projection.interfaces index;
      embedded = builtins.elemAt projection.value.interface_documents index;
    in
      retained.descriptor
      == embedded.descriptor
      && retained.value == embedded.document)
    (builtins.genList (index: index) (builtins.length projection.interfaces));
  checkedPackageInputs =
    if packageRoots == null || packages == []
    then true
    else common.fail "static ability contract accepts packageRoots or packages, never both";
  resolvePackageOutput = payload: selector: let
    package =
      if selector.package == "self"
      then payload
      else if builtins.isAttrs packageRegistry && builtins.hasAttr selector.package packageRegistry
      then builtins.getAttr selector.package packageRegistry
      else common.fail "ability selector names unknown package '${selector.package}'";
    projectedOutputs = package.abilities.projection.artifactOutputs or {};
    selectedProjection = projectedOutputs.${selector.output} or null;
    outputs = lib.unique ((package.outputs or ["out"]) ++ builtins.attrNames projectedOutputs);
  in
    if !(builtins.elem selector.output outputs)
    then common.fail "ability selector names missing output '${selector.output}' on package '${selector.package}'"
    else if selectedProjection != null
    then selectedProjection.output
    else if selector.output == "out"
    then package.out or package
    else builtins.getAttr selector.output package;
  contractPaths = map builtins.toString contracts;
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
  checkedPackages =
    if
      lib.all (entry:
        builtins.isAttrs entry
        && validPackageProjection entry.manifest)
      selectedPackages
      && builtins.isAttrs packageRegistry
      && lib.all (entry:
        entry.manifest.value.package.name
        == entry.payload.pname
        && entry.manifest.value.package.version == entry.payload.version)
      selectedPackages
      && lib.all (entry: builtins.elem (builtins.toString entry.payload) runtimeRootPaths) selectedPackages
      && builtins.length packagePaths == builtins.length (lib.unique (map (entry: entry.manifest) packagePaths))
    then packagePaths
    else common.fail "static ability contract packages must name unique AOS ability companions";
  packageResolutions = builtins.genList (packageIndex: let
    entry = builtins.elemAt selectedPackages packageIndex;
    selectorArtifacts = builtins.genList (selectorIndex: let
      selector = builtins.elemAt entry.manifest.value.artifacts selectorIndex;
      selected = resolvePackageOutput entry.payload selector;
    in {
      inherit (selector) package output;
      path = builtins.toString selected;
      graph = "abilityResolution${toString packageIndex}Selector${toString selectorIndex}";
      graphPath = selected;
    }) (builtins.length entry.manifest.value.artifacts);
  in {
    manifest = builtins.toString entry.manifest.document;
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
      (builtins.toJSON resolution.resolution);
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
              ${lib.escapeShellArg (builtins.toString entry.manifest.document)} \
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
        && (contract.passthru.ociStaticAbilityContract or false)
        && contract.passthru.artifactClass == checkedArtifactClass
        && contract.passthru.executionStage == checkedExecutionStage)
      contracts
    then contractPaths
    else common.fail "static ability contract inputs must be produced by mkStaticAbilityContract";
  packageAbilityContracts =
    if platformMode
    then resolvedPackageContracts
    else lib.unique (lib.concatMap (contract: contract.passthru.packageAbilityContracts) contracts);
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
        checkedPackages
        checkedRuntimeRoots
        checkedContracts
        checkedPackageInputs
      ]
      true
    else common.fail "static ability contract requires exactly one platform package set or a non-empty contract set";
  assemblyPackages = builtins.genList (index: {
    payload = (builtins.elemAt packagePaths index).payload;
    manifest = builtins.toString (builtins.elemAt resolvedPackageContracts index);
  }) (builtins.length packagePaths);
  assemblySpec = builtins.toFile "${pname}-static-ability-assembly.json" (builtins.toJSON {
    inherit schema artifactClass executionStage;
    mediaType = mediaType;
    platform = checkedPlatform;
    packages = assemblyPackages;
    contracts = checkedContracts;
  });
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [abilityContractValidator] ++ packageAbilityContracts ++ contracts;
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

    passthru = {
      ociStaticAbilityContract = true;
      inherit mediaType schema artifactClass executionStage checkedPlatform runtimeRootPaths;
      inherit packageAbilityContracts;
      inputContractPaths = contractPaths;
      selectedPayloadPaths = map (entry: entry.payload) packagePaths;
    };

    meta.description = "Closed static ability contract for an AOS OCI artifact";
  })
