##! Resolves symbolic package outputs inside one authenticated dependency closure.
{}: let
  packageNameFor = package:
    if package ? contract
    then package.contract.value.package.name
    else package.pname or package.name or (throw "selected dependency has no package identity");

  dependencyClosureFor = owner: let
    visit = seen: pending:
      if pending == []
      then seen
      else let
        package = builtins.head pending;
        remaining = builtins.tail pending;
        dependencies = remaining ++ (package.runtimeDeps or []);
      in
        if !(package ? contract)
        then visit seen dependencies
        else let
          name = packageNameFor package;
        in
          if builtins.hasAttr name seen
          then
            if builtins.toString seen.${name} == builtins.toString package
            then visit seen remaining
            else throw "package '${packageNameFor owner}' has ambiguous authenticated dependency outputs for '${name}'"
          else visit (seen // {${name} = package;}) dependencies;
  in
    visit {} [owner];

  authenticatedPackageOutputFor = {
    package,
    selector,
  }: let
    ownerName = packageNameFor package;
    normalizedSelector = builtins.removeAttrs selector ["_type"];
    selectorDeclared = builtins.elem normalizedSelector package.contract.selectors;
    dependencies = dependencyClosureFor package;
    selectedPackage =
      if builtins.elem normalizedSelector.package ["self" ownerName]
      then package
      else dependencies.${normalizedSelector.package}
        or (throw "package '${ownerName}' selector '${builtins.toJSON normalizedSelector}' is outside its authenticated dependency closure");
  in
    if !selectorDeclared
    then throw "package '${ownerName}' requested undeclared output selector '${builtins.toJSON normalizedSelector}'"
    else if normalizedSelector.package == "self" && normalizedSelector.output == "module"
    then package.module
    else if normalizedSelector.output == (selectedPackage.outputName or "out")
    then selectedPackage
    else selectedPackage.${normalizedSelector.output}
      or (throw "package '${ownerName}' selector '${builtins.toJSON normalizedSelector}' names a missing output");

  authenticatedPackageOutputsFor = package: let
    ownerName = packageNameFor package;
    closure = dependencyClosureFor package;
    runtimeDependencies = builtins.listToAttrs (builtins.concatMap (name:
      if name == ownerName
      then []
      else let
        dependency = closure.${name};
        selector = {
          package = name;
          output = dependency.outputName or "out";
        };
      in [
        {
          name = builtins.toJSON selector;
          value = builtins.toString dependency;
        }
      ])
    (builtins.attrNames closure));
    declaredDependencies = builtins.listToAttrs (builtins.map (selector: {
        name = builtins.toJSON selector;
        value = builtins.toString (authenticatedPackageOutputFor {
          inherit package selector;
        });
      })
      package.contract.selectors);
  in {
    self = builtins.toString package;
    dependencies = runtimeDependencies // declaredDependencies;
  };

  authenticatedPackageModuleRecordFor = package: {
    name = packageNameFor package;
    version = package.version or "0";
    configRoot = builtins.toString package.module;
    module = "${package.module}/module.nix";
    outputs = authenticatedPackageOutputsFor package;
  };

  authenticatedPackageProjectionFor = package: let
    identity = package.contract.value.package or null;
    valid =
      builtins.isAttrs package
      && package ? abilities
      && package ? contract
      && package ? module
      && builtins.isAttrs identity
      && builtins.attrNames identity == ["name" "version"]
      && builtins.isString identity.name
      && builtins.isString identity.version
      && package.contract.value.package_module != null;
  in
    if !valid
    then throw "authenticated package projection requires one native package ability contract and module"
    else
      checkedAuthenticatedPackageProjection {
        _type = "aos-checked-package-projection";
        payload = package;
        inherit (package) contract;
        origin = {
          _type = "aos-authenticated-package-origin";
          package = {
            inherit (identity) name version;
            document = builtins.toString package.contract.document;
          };
          packageArtifactFor = selector:
            authenticatedPackageOutputFor {
              inherit package selector;
            };
        };
      };

  canonicalizeAuthenticatedPackages = packages: let
    grouped = builtins.groupBy packageNameFor packages;
    canonicalizePackage = name: candidates: let
      ordered =
        builtins.sort (
          left: right: builtins.toString left < builtins.toString right
        )
        candidates;
      selected = builtins.head ordered;
      sameContract = candidate:
        candidate.contract.value
        == selected.contract.value
        && builtins.toString candidate.contract.document
        == builtins.toString selected.contract.document
        && builtins.toString candidate.module == builtins.toString selected.module;
    in
      if builtins.all sameContract ordered
      then selected
      else throw "selected outputs carry conflicting authenticated contracts for package '${name}'";
  in
    builtins.map
    (name: canonicalizePackage name grouped.${name})
    (builtins.attrNames grouped);

  checkedPackageOutputSelector = selector: let
    normalized =
      if builtins.isAttrs selector
      then builtins.removeAttrs selector ["_type"]
      else null;
    valid =
      builtins.isAttrs selector
      && builtins.all
      (name: builtins.elem name ["_type" "package" "output"])
      (builtins.attrNames selector)
      && (!selector ? _type || selector._type == "aos-package-output-selector")
      && builtins.isAttrs normalized
      && builtins.attrNames normalized == ["output" "package"]
      && builtins.isString normalized.package
      && normalized.package != ""
      && builtins.isString normalized.output
      && normalized.output != "";
  in
    if valid
    then selector
    else throw "authenticated package output selector has a non-canonical shape";

  checkedAuthenticatedPackageProjection = projection: let
    projectionAttrs = builtins.isAttrs projection;
    contract =
      if projectionAttrs
      then projection.contract or null
      else null;
    origin =
      if projectionAttrs
      then projection.origin or null
      else null;
    identity =
      if builtins.isAttrs origin
      then origin.package or null
      else null;
    contractIdentity =
      if builtins.isAttrs contract && builtins.isAttrs (contract.value or null)
      then contract.value.package or null
      else null;
    authoritativeSelectors =
      if builtins.isAttrs contract && builtins.isAttrs (contract.value or null)
      then contract.value.artifacts or null
      else null;
    validContract =
      builtins.isAttrs contract
      && builtins.attrNames contract == ["document" "selectors" "value"]
      && (builtins.isString contract.document || (builtins.isAttrs contract.document && contract.document ? outPath))
      && builtins.isList contract.selectors
      && builtins.all
      (selector: (builtins.tryEval (builtins.deepSeq (checkedPackageOutputSelector selector) true)).success)
      contract.selectors
      && builtins.isAttrs contract.value
      && builtins.isAttrs contractIdentity
      && builtins.attrNames contractIdentity == ["name" "version"]
      && builtins.isString contractIdentity.name
      && contractIdentity.name != ""
      && builtins.isString contractIdentity.version
      && contractIdentity.version != ""
      && builtins.isList authoritativeSelectors
      && contract.selectors == authoritativeSelectors;
    validOrigin =
      builtins.isAttrs origin
      && builtins.attrNames origin == ["_type" "package" "packageArtifactFor"]
      && origin._type == "aos-authenticated-package-origin"
      && builtins.isAttrs identity
      && builtins.attrNames identity == ["document" "name" "version"]
      && builtins.isString identity.document
      && builtins.isString identity.name
      && identity.name != ""
      && builtins.isString identity.version
      && identity.version != ""
      && builtins.isFunction origin.packageArtifactFor
      && validContract
      && identity.name == contractIdentity.name
      && identity.version == contractIdentity.version
      && identity.document == builtins.toString contract.document;
    validPayload =
      projectionAttrs
      && builtins.isAttrs (projection.payload or null)
      && builtins.isString (projection.payload.pname or null)
      && builtins.isString (projection.payload.version or null)
      && validContract
      && projection.payload.pname == contractIdentity.name
      && projection.payload.version == contractIdentity.version;
    valid =
      projectionAttrs
      && builtins.attrNames projection == ["_type" "contract" "origin" "payload"]
      && projection._type == "aos-checked-package-projection"
      && validPayload
      && validContract
      && validOrigin;
  in
    if valid
    then projection
    else throw "authenticated package projection has a non-canonical shape";

  authenticatedProjectionOutputFor = {
    projection,
    selector,
  }: let
    checkedProjection = checkedAuthenticatedPackageProjection projection;
    checkedSelector = checkedPackageOutputSelector selector;
  in
    checkedProjection.origin.packageArtifactFor checkedSelector;

  authenticatedModuleRecordIdentity = record: let
    exactRecordShape =
      builtins.isAttrs record
      && builtins.attrNames record
      == [
        "configRoot"
        "module"
        "name"
        "outputs"
        "version"
      ];
    exactOutputsShape =
      exactRecordShape
      && builtins.isAttrs record.outputs
      && builtins.attrNames record.outputs == ["dependencies" "self"];
    dependencies =
      if exactOutputsShape
      then record.outputs.dependencies
      else null;
  in
    if
      !exactRecordShape
      || !exactOutputsShape
      || !builtins.isAttrs dependencies
      || !builtins.isString record.name
      || !builtins.isString record.version
    then throw "authenticated module record has a non-canonical shape"
    else {
      inherit (record) name version;
      configRoot = builtins.toString record.configRoot;
      module = builtins.toString record.module;
      outputs = {
        self = builtins.toString record.outputs.self;
        dependencies = builtins.mapAttrs (_: builtins.toString) dependencies;
      };
    };

  canonicalizeAuthenticatedModuleRecords = records: let
    grouped =
      builtins.groupBy
      (record: (authenticatedModuleRecordIdentity record).name)
      records;
    canonicalizePackage = name: candidates: let
      byEntrypoint =
        builtins.groupBy
        (record:
          builtins.unsafeDiscardStringContext
          (
            authenticatedModuleRecordIdentity record
          ).module)
        candidates;
    in
      builtins.map
      (entrypoint: let
        entrypointCandidates = byEntrypoint.${entrypoint};
        identities = builtins.map authenticatedModuleRecordIdentity entrypointCandidates;
        expected = builtins.head identities;
      in
        if !builtins.all (identity: identity == expected) identities
        then throw "authenticated module records conflict for package '${name}' entrypoint '${entrypoint}'"
        else builtins.head entrypointCandidates)
      (builtins.attrNames byEntrypoint);
  in
    builtins.concatMap
    (name: canonicalizePackage name grouped.${name})
    (builtins.attrNames grouped);

  selectAuthenticatedPackageModuleRecords = packages: records:
    builtins.map (package: let
      name = packageNameFor package;
      version = package.version or "0";
      self = builtins.toString package;
      matches =
        builtins.filter
        (record:
          record.name
          == name
          && (record.version or null) == version
          && (record.outputs.self or null) == self)
        records;
    in
      if builtins.length matches != 1
      then throw "stage package '${name}' does not identify one exact authenticated package module record"
      else builtins.head matches)
    packages;
in {
  inherit
    authenticatedPackageOutputFor
    authenticatedPackageOutputsFor
    authenticatedPackageModuleRecordFor
    authenticatedPackageProjectionFor
    canonicalizeAuthenticatedPackages
    checkedAuthenticatedPackageProjection
    authenticatedProjectionOutputFor
    authenticatedModuleRecordIdentity
    canonicalizeAuthenticatedModuleRecords
    selectAuthenticatedPackageModuleRecords
    ;
}
