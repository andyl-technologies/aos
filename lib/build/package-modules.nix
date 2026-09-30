##! Constructs exact package module inputs independently of activation contracts.
{}: let
  packageNameFor = package: package.pname or package.name;

  recordFor = package: let
    name = packageNameFor package;
    outputEntry = dependency: {
      name = builtins.toJSON {
        package = packageNameFor dependency;
        output = dependency.outputName or "out";
      };
      value = builtins.toString dependency;
    };
    entries =
      builtins.map outputEntry (package.runtimeDeps or [])
      ++ [
        {
          name = builtins.toJSON {
            package = name;
            output = "module";
          };
          value = builtins.toString package.module;
        }
      ];
    dependencies = builtins.foldl' (outputs: entry:
      if outputs ? ${entry.name} && outputs.${entry.name} != entry.value
      then throw "Package '${name}' has conflicting output '${entry.name}'."
      else outputs // {${entry.name} = entry.value;}) {}
    entries;
  in {
    inherit name;
    version = package.version or "0";
    configRoot = builtins.toString package.module;
    module = "${package.module}/module.nix";
    outputs = {
      self = builtins.toString (package.out or package);
      inherit dependencies;
    };
  };

  identity = record: let
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

  canonicalize = records: let
    grouped =
      builtins.groupBy
      (record: (identity record).name)
      records;
    canonicalizePackage = name: candidates: let
      byEntrypoint =
        builtins.groupBy
        (record:
          builtins.unsafeDiscardStringContext
          (
            identity record
          ).module)
        candidates;
    in
      builtins.map
      (entrypoint: let
        entrypointCandidates = byEntrypoint.${entrypoint};
        identities = builtins.map identity entrypointCandidates;
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

  select = packages: records:
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
in {inherit recordFor identity canonicalize select;}
