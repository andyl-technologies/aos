##! Exact package module records and their explicit module dependency closure.
{verifyMetadata ? true}: let
  artifacts = import ../packages/artifacts.nix {};
  dependencies = import ../packages/module-dependencies.nix;
  inherit (artifacts) nameFor;
  packageReference =
    if verifyMetadata
    then artifacts.canonicalReference
    else package: artifacts.canonical (artifacts.reference package);
  runtimeReferences =
    if verifyMetadata
    then artifacts.canonicalDependencies
    else package: artifacts.keyed (package.runtimeDeps or []);
  recordFor = package: let
    osVersion = package.osVersion or null;
    requirements =
      builtins.filter (value: value != null)
      (map (dependencies.requirement nameFor) (package.moduleDeps or []));
  in
    {
      name = nameFor package;
      version = package.version or "0";
      configRoot = "${package.module}";
      module = "${package.module}/module.nix";
      artifacts = {
        package = packageReference package;
        dependencies = runtimeReferences package;
      };
    }
    // builtins.removeAttrs (artifacts.releaseIdentity package) ["name" "version"]
    // (
      if osVersion == null
      then {}
      else {inherit osVersion;}
    )
    // (
      if requirements == []
      then {}
      else {moduleRequirements = requirements;}
    );
  identity = record:
    if
      builtins.removeAttrs record ["artifacts" "configRoot" "module" "name" "version" "osVersion" "moduleRequirements" "versionRequirement"]
      != {}
      || !(builtins.all (name: record ? ${name}) ["artifacts" "configRoot" "module" "name" "version"])
    then throw "Package module record has a non-canonical shape."
    else
      (builtins.removeAttrs record (
        (
          if (record.osVersion or null) == null
          then ["osVersion"]
          else []
        )
        ++ (
          if (record.versionRequirement or null) == null
          then ["versionRequirement"]
          else []
        )
        ++ (
          if (record.moduleRequirements or []) == []
          then ["moduleRequirements"]
          else []
        )
      ))
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
      wanted = artifacts.canonicalReference package;
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
          artifact = packageReference package;
          runtimeDependencies = builtins.attrValues (runtimeReferences package);
          module =
            if package ? module
            then recordFor package
            else null;
          dependencies = dependencies.references artifacts.moduleReference (package.moduleDeps or []);
        };
      in
        builtins.seq record.dependencies (
          if selected ? ${name}
          then
            if record == selected.${name}.identity
            then visit selected rest
            else throw "Module dependency '${name}' has conflicting package identities in: ${builtins.concatStringsSep ", " (builtins.filter (field: record.${field} != selected.${name}.identity.${field}) (builtins.attrNames record))}. Catalogs: ${builtins.toJSON [(artifacts.metadata record.artifact) (artifacts.metadata selected.${name}.identity.artifact)]}"
          else
            visit (selected
              // {
                ${name} = {
                  inherit package;
                  identity = record;
                };
              }) ((builtins.map dependencies.seed (package.moduleDeps or [])) ++ rest)
        );
  in
    visit {} packages;
  closure = packages: builtins.filter (record: record != null) (builtins.map (entry: entry.identity.module) (resolved packages));
  # Source companions use the same checked closure as module evaluation. The
  # first selected output supplies the envelope; identity comparison above
  # ensures other outputs of that package carry the same module context.
  envelopes = packages:
    builtins.listToAttrs (builtins.map (entry: {
        name = entry.identity.module.name;
        value = entry.package.deploymentArtifact;
      })
      (builtins.filter (entry: entry.identity.module != null) (resolved packages)));
  payloads = packages: artifacts.unique (builtins.map artifacts.reference packages);
in {inherit nameFor recordFor identity canonicalize select closure envelopes payloads resolved;}
