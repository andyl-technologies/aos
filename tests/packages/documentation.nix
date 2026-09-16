##! tests/packages/documentation.nix — package documentation authority gate.
{
  lib,
  pkgs,
  ...
}: let
  expectedAbilityFields = [
    "guarantees"
    "implementations"
    "interfaces"
    "requirementTemplates"
  ];
  legacyPassthruFields = [
    "abilities"
    "abilityModule"
    "abilityModuleSource"
    "configModule"
  ];
  abilityPackages = lib.filterAttrs (_: value: let
    evaluated = builtins.tryEval value;
  in
    evaluated.success
    && builtins.isAttrs evaluated.value
    && lib.isDerivation evaluated.value
    && evaluated.value ? abilities)
  pkgs;
  packageNames = builtins.attrNames abilityPackages;
  projectionPaths =
    builtins.map
    (name: abilityPackages.${name}.contract.document)
    packageNames;
  countRefinedSchemas = value:
    if builtins.isList value
    then builtins.foldl' (count: item: count + countRefinedSchemas item) 0 value
    else if builtins.isAttrs value
    then
      (
        if (value.kind or null) == "refined"
        then 1
        else 0
      )
      + builtins.foldl' (
        count: name: count + countRefinedSchemas value.${name}
      )
      0 (builtins.attrNames value)
    else 0;
  productionRefinedSchemaCount =
    builtins.foldl' (
      count: name:
        count + countRefinedSchemas abilityPackages.${name}.contract.value
    )
    0
    packageNames;

  discoverNixSources = directory: prefix:
    lib.concatMap (
      name: let
        entryType = (builtins.readDir directory).${name};
        relative = "${prefix}${name}";
      in
        if entryType == "directory"
        then discoverNixSources (directory + "/${name}") "${relative}/"
        else
          lib.optional (
            entryType
            == "regular"
            && builtins.match ".*\\.nix" name != null
            && relative != "default.nix"
          ) {
            inherit relative;
            source = directory + "/${name}";
          }
    ) (builtins.attrNames (builtins.readDir directory));
  packageSources = discoverNixSources ../../pkgs "";
  importsPrivateLibrary = source:
    builtins.any (
      line:
        builtins.match ".*import[[:space:]]+(\\.\\./)+lib/.*" line
        != null
        || builtins.match ".*import[[:space:]]+\\((\\.\\./)+lib/.*" line != null
    ) (lib.splitString "\n" (builtins.readFile source));
  privateLibraryImports =
    builtins.map
    (entry: entry.relative)
    (builtins.filter (entry: importsPrivateLibrary entry.source) packageSources);

  invalidPackages = builtins.filter (name: let
    package = abilityPackages.${name};
    projectedAbilities = {
      inherit (package.contract.value) guarantees interfaces;
      implementations = builtins.listToAttrs (builtins.map (implementation: {
          name = implementation.name;
          value = implementation;
        })
        package.contract.value.implementation.providers);
      requirementTemplates = builtins.listToAttrs (builtins.map (requirement: {
          name = requirement.alias;
          value = requirement;
        })
        package.contract.value.requirements);
    };
    evaluatedAbilities = builtins.tryEval (builtins.toJSON {
      interfaceAliases = builtins.attrNames package.abilities.interfaces;
      implementationAliases = builtins.attrNames package.abilities.implementations;
      requirementAliases = builtins.attrNames package.abilities.requirementTemplates;
      guaranteeAliases = builtins.attrNames package.abilities.guarantees;
    });
    abilities =
      if evaluatedAbilities.success
      then builtins.fromJSON evaluatedAbilities.value
      else {};
  in
    !evaluatedAbilities.success
    || !(abilities ? interfaceAliases)
    || !(abilities ? implementationAliases)
    || !(abilities ? requirementAliases)
    || !(abilities ? guaranteeAliases)
    || !(builtins.isList abilities.interfaceAliases)
    || !(builtins.isList abilities.implementationAliases)
    || !(builtins.isList abilities.requirementAliases)
    || !(builtins.isList abilities.guaranteeAliases)
    || builtins.attrNames package.abilities != expectedAbilityFields
    || package.abilities != projectedAbilities
    || lib.hasInfix "\"_type\"" (builtins.toJSON package.contract.value)
    || builtins.any (field: builtins.hasAttr field (package.passthru or {})) legacyPassthruFields
    || !(package ? module)
    || !(package ? contract))
  packageNames;
in
  if !builtins.isFunction lib.mkArtifactConsumptionAudit
  then throw "lib.mkArtifactConsumptionAudit must expose the package-safe artifact audit constructor"
  else if privateLibraryImports != []
  then throw "package definitions import private library paths: ${builtins.concatStringsSep ", " privateLibraryImports}"
  else if invalidPackages != []
  then throw "package ability documentation projections are invalid: ${builtins.concatStringsSep ", " invalidPackages}"
  else if productionRefinedSchemaCount == 0
  then throw "package ability documentation projections contain no refined schemas"
  else
    pkgs.mkDerivation {
      pname = "package-documentation-policy-check";
      version = "0";
      src = null;
      buildDeps = [pkgs.aos-ability-contract-validator];
      outputChecks = {};
      phases = [
        {
          name = "check";
          script = ''
            ${builtins.concatStringsSep "\n" (builtins.map (path: "aos-ability-contract-validator package-projection ${lib.escapeShellArg path}") projectionPaths)}
            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
