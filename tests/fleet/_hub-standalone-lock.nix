# A standalone observer uses only registry versions in its runtime's vendor.
# Compare checksums and complete source identities as well as names and versions.
workspaceLock: standaloneLock: let
  packageKey = package:
    builtins.toJSON {
      inherit (package) name version source;
      checksum = package.checksum or null;
    };

  workspacePackages = (builtins.fromTOML (builtins.readFile workspaceLock)).package;
  standalonePackages = (builtins.fromTOML (builtins.readFile standaloneLock)).package;
  registryPackages = builtins.filter (package: package ? source) workspacePackages;
  available = builtins.listToAttrs (map (package: {
      name = packageKey package;
      value = true;
    })
    registryPackages);
in
  builtins.all
  (package: !(package ? source) || builtins.hasAttr (packageKey package) available)
  standalonePackages
