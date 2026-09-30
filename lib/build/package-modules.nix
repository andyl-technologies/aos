##! Exact package module records and their explicit module dependency closure.
{}: let
  artifacts = import ../packages/artifacts.nix {};
  inherit (artifacts) nameFor;
  recordFor = package: {
    name = nameFor package;
    version = package.version or "0";
    configRoot = builtins.toString package.module;
    module = "${package.module}/module.nix";
    artifacts = {
      package = artifacts.reference package;
      dependencies = artifacts.keyed (package.runtimeDeps or []);
    };
  };
  identity = record:
    if builtins.attrNames record != ["artifacts" "configRoot" "module" "name" "version"]
    then throw "Package module record has a non-canonical shape."
    else
      record
      // {
        configRoot = builtins.toString record.configRoot;
        module = builtins.toString record.module;
      };
  canonicalize = records:
    builtins.attrValues (builtins.foldl' (result: record: let
      checked = identity record;
      previous = result.${checked.name} or checked;
    in
      if identity previous != checked
      then throw "Package module '${checked.name}' has conflicting identities."
      else result // {${checked.name} = record;}) {}
    records);
  select = packages: records:
    builtins.map (package: let
      wanted = artifacts.reference package;
      matches = builtins.filter (record: record.name == wanted.name && record.artifacts.package == wanted) records;
    in
      if builtins.length matches != 1
      then throw "Package '${wanted.name}' does not identify one exact module record."
      else builtins.head matches)
    packages;
  resolved = packages: let
    visit = selected: pending:
      if pending == []
      then builtins.attrValues selected
      else let
        package = builtins.head pending;
        rest = builtins.tail pending;
        name = nameFor package;
        record = {
          artifact = artifacts.reference package;
          runtimeDependencies = builtins.map artifacts.reference (package.runtimeDeps or []);
          module =
            if package ? module
            then recordFor package
            else null;
          dependencies = builtins.map artifacts.moduleReference (package.moduleDeps or []);
        };
      in
        if selected ? ${name}
        then
          if record == selected.${name}
          then visit selected rest
          else throw "Module dependency '${name}' has conflicting package identities."
        else visit (selected // {${name} = record;}) ((package.moduleDeps or []) ++ rest);
  in
    visit {} packages;
  closure = packages: builtins.filter (record: record != null) (builtins.map (record: record.module) (resolved packages));
  payloads = packages: artifacts.unique (builtins.concatLists (builtins.map (record: [record.artifact] ++ record.runtimeDependencies) (resolved packages)));
in {inherit nameFor recordFor identity canonicalize select closure payloads;}
