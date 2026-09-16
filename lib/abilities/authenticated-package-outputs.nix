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
        name = packageNameFor package;
        remaining = builtins.tail pending;
      in
        if builtins.hasAttr name seen
        then
          if builtins.toString seen.${name} == builtins.toString package
          then visit seen remaining
          else throw "package '${packageNameFor owner}' has ambiguous authenticated dependency outputs for '${name}'"
        else visit (seen // {${name} = package;}) (remaining ++ (package.runtimeDeps or []));
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
      else
        dependencies.${normalizedSelector.package}
        or (throw "package '${ownerName}' selector '${builtins.toJSON normalizedSelector}' is outside its authenticated dependency closure");
  in
    if !selectorDeclared
    then throw "package '${ownerName}' requested undeclared output selector '${builtins.toJSON normalizedSelector}'"
    else if normalizedSelector.package == "self" && normalizedSelector.output == "module"
    then package.module
    else if normalizedSelector.output == (selectedPackage.outputName or "out")
    then selectedPackage
    else
      selectedPackage.${normalizedSelector.output}
      or (throw "package '${ownerName}' selector '${builtins.toJSON normalizedSelector}' names a missing output");

  authenticatedPackageOutputsFor = package: let
    dependencies = builtins.listToAttrs (builtins.map (selector: {
        name = builtins.toJSON selector;
        value = builtins.toString (authenticatedPackageOutputFor {
          inherit package selector;
        });
      })
      package.contract.selectors);
  in {
    self = builtins.toString package;
    inherit dependencies;
  };

  authenticatedPackageModuleRecordFor = package: {
    name = packageNameFor package;
    version = package.version or "0";
    configRoot = builtins.toString package.module;
    module = "${package.module}/module.nix";
    outputs = authenticatedPackageOutputsFor package;
  };

  selectAuthenticatedPackageModuleRecords = packages: records:
    builtins.map (package: let
      name = packageNameFor package;
      version = package.version or "0";
      self = builtins.toString package;
      matches = builtins.filter
        (record:
          record.name == name
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
    selectAuthenticatedPackageModuleRecords
    ;
}
