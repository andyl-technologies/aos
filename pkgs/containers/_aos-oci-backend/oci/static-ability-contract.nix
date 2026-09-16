##! Package-owned static OCI ability contracts.
##!
##! This is the local orchestration boundary for checked package projections.
##! Each projection carries its authenticated package origin and a resolver
##! closed over that origin's exact retained outputs. The builder never performs
##! package-name lookup or infers provenance from a selector string. Container
##! contracts preserve their existing schema. Bootable host and initrd contracts
##! add an explicit execution stage so an artifact cannot claim that a later
##! manager satisfies an early consumer. Every form retains unresolved required
##! bindings while carrying no runtime grants.
{
  lib,
  mkDerivation,
  abilityContractValidator,
  common,
}: {
  platform ? null,
  targetPlatform ? null,
  packageProjections ? [],
  runtimeRoots ? [],
  contracts ? [],
  pname ? "aos-container-static-ability-contract",
  artifactClass ? "container",
  executionStage ? null,
}: let
  packageOrigins = import ./checked-package-origin.nix {inherit common;};
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
  selectedPackages = map packageOrigins.checkedProjection packageProjections;
  payloadPaths = map (entry: builtins.toString entry.payload) selectedPackages;
  validPackageContract = contract:
    builtins.isAttrs contract
    && builtins.attrNames contract == ["document" "selectors" "value"]
    && builtins.isAttrs contract.document
    && contract.document ? outPath
    && builtins.isList contract.selectors
    && builtins.isAttrs contract.value
    && contract.selectors == contract.value.artifacts;
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
      && lib.all (entry:
        entry.origin.package.name == entry.contract.value.package.name
        && entry.origin.package.version == entry.contract.value.package.version
        && entry.origin.package.document == builtins.toString entry.contract.document)
      selectedPackages
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
      selected = packageOrigins.resolve entry selector;
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
  retainedBootReferences = retainedPackageContractArtifacts ++ checkedRuntimeRoots;
  retainBootReferences = lib.concatStringsSep "\n" (builtins.genList (index: let
      reference = builtins.elemAt retainedBootReferences index;
    in ''
      ln -s ${lib.escapeShellArg (builtins.toString reference)} \
        "$out/retained-references/${builtins.toString index}"
    '')
    (builtins.length retainedBootReferences));
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
    # Bootable contracts are themselves closure roots. Their checked package
    # documents and runtime roots must remain live after the builder exits.
    # Container publication retains those inputs through its separate closure.
    unsafeDiscardReferences.out = artifactClass == "container";
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
          ${lib.optionalString (artifactClass == "bootable") ''
            mkdir -p "$out/retained-references"
            ${retainBootReferences}
          ''}
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
