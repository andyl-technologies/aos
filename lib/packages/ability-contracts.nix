##! Projects versioned contracts from module declarations without forcing effects.
{lib}: let
  modules = import ../build/package-modules.nix {verifyMetadata = false;};
  dependencies = import ./module-dependencies.nix;
  artifacts = import ./artifacts.nix {};
  semver = import ./semver.nix;
  fromConfig = config:
    builtins.mapAttrs (_: ability: {
      inherit (ability) version;
      owner = ability.versionOwner;
    }) (lib.filterAttrs (_: ability: ability.version != null) config.aos.abilities);
  fromRecords = records:
    fromConfig
    (lib.evalModules {
      inherit lib;
      modules = [../effects/module.nix];
      packageModules = records;
    }).config;
  forPackages = packages: fromRecords (modules.closure packages);
  owned = package: contracts:
    builtins.mapAttrs (_: contract: {inherit (contract) version;})
    (lib.filterAttrs (_: contract: contract.owner == artifacts.nameFor package) contracts);
  exports = package: owned package (forPackages [package]);
  checkRecords = records: config: let
    declared = fromConfig config;
  in
    builtins.all (record: let
      actual =
        builtins.mapAttrs (_: contract: {inherit (contract) version;})
        (lib.filterAttrs (_: contract: contract.owner == record.name) declared);
    in
      if actual == (record.abilityExports or {})
      then true
      else throw "Package '${record.name}' evaluated ability versions differ from its authenticated exports.")
    records;
  requirements = packages:
    builtins.concatLists (map (entry:
      builtins.concatLists (map (dependency: let
        normalized = dependencies.normalize dependency;
      in
        if normalized.requirements == null
        then []
        else [
          ({
              owner = artifacts.nameFor entry.package;
              package = artifacts.nameFor normalized.package;
            }
            // normalized.requirements)
        ])
      (entry.package.moduleDeps or []))) (modules.resolved packages));
  checkSeeds = packages: contracts:
    builtins.all (requirement: let
      candidates =
        builtins.filter (entry: artifacts.nameFor entry.package == requirement.package)
        (modules.resolved packages);
      selected = (builtins.head candidates).package;
      selectedExports = owned selected contracts;
      matchesAbilities = builtins.all (name:
        selectedExports ? ${name} && semver.matches requirement.abilities.${name} selectedExports.${name}.version)
      (builtins.attrNames requirement.abilities);
      matchesPackage =
        !(requirement ? packageVersion)
        || semver.matches requirement.packageVersion (selected.version or "0");
    in
      if matchesAbilities && matchesPackage
      then true
      else throw "Module dependency '${requirement.package}' selected by '${requirement.owner}' does not satisfy its declared package/ability compatibility ranges.")
    (requirements packages);
in {inherit fromConfig fromRecords forPackages owned exports requirements checkSeeds checkRecords;}
