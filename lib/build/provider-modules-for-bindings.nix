##! Resolves selected implementation module locators through authenticated package records.
{
  lib,
  abilities,
  packageModules,
  bindings,
}: let
  checkedPackageModules =
    lib.abilities.canonicalizeAuthenticatedModuleRecords packageModules;
  packageRecordFor = implementationName: implementation: let
    packageName =
      if implementation.package == null
      then throw "selected implementation '${implementationName}' has no authenticated package owner"
      else implementation.package;
    matches =
      builtins.filter
      (record: record.name == packageName)
      checkedPackageModules;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else
      throw
      "selected implementation '${implementationName}' does not identify one authenticated package module record";
  artifactFor = record: selector: let
    normalized = builtins.removeAttrs selector ["_type"];
    key = builtins.toJSON normalized;
    selectsSelf =
      normalized.package
      == record.name
      && normalized.output == "out";
  in
    if selectsSelf
    then record.outputs.self
    else record.outputs.dependencies.${key}
      or (throw "selected provider '${record.name}' requested unauthenticated artifact ${key}");
  moduleForBinding = binding: let
    implementation =
      abilities.implementations.${binding.implementation}
      or (throw "binding selects absent implementation '${binding.implementation}'");
    locator = implementation.providerModule;
  in
    if locator == null
    then []
    else let
      record = packageRecordFor binding.implementation implementation;
      configRoot = artifactFor record locator.artifact;
      components = lib.splitString "/" locator.path;
    in
      if builtins.any (component: component == "" || component == "." || component == "..") components
      then throw "provider module '${binding.implementation}' has a non-normalized authenticated path"
      else [
        {
          inherit (record) name version outputs;
          inherit configRoot;
          module = "${configRoot}/${locator.path}";
        }
      ];
in
  lib.abilities.canonicalizeAuthenticatedModuleRecords (
    builtins.concatMap moduleForBinding (builtins.attrValues bindings)
  )
