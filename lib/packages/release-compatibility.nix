##! Checks release constraints authored once in package dependency declarations.
{lib}: let
  modules = import ../build/package-modules.nix {};
  dependencies = import ./module-dependencies.nix;
  artifacts = import ./artifacts.nix {};
  semver = import ./semver.nix;
  requirements = packages:
    builtins.concatLists (map (entry:
      builtins.concatLists (map (dependency: let
        requirement = dependencies.requirement artifacts.nameFor dependency;
      in
        lib.optional (requirement != null)
        (requirement // {owner = artifacts.nameFor entry.package;}))
      (entry.package.moduleDeps or []))) (modules.resolved packages));
  checkSeeds = packages:
    builtins.all (entry:
      builtins.all (dependency: let
        normalized = dependencies.normalize dependency;
      in
        if normalized.requirements == null
        then true
        else if semver.matches normalized.requirements.packageVersion (normalized.package.version or "0")
        then true
        else throw "Module dependency '${artifacts.nameFor normalized.package}' selected by '${artifacts.nameFor entry.package}' does not satisfy packageVersion '${normalized.requirements.packageVersion}'.")
      (entry.package.moduleDeps or [])) (modules.resolved packages);
  osRequirements = packages:
    builtins.concatLists (map (entry: let
      osVersion = entry.package.osVersion or null;
    in
      if osVersion == null
      then []
      else
        builtins.deepSeq (semver.parseRequirement osVersion)
        [
          {
            owner = artifacts.nameFor entry.package;
            inherit osVersion;
          }
        ])
    (modules.resolved packages));
  checkOsRequirements = requirements: osRelease:
    builtins.all (requirement:
      if osRelease == null
      then throw "Package '${requirement.owner}' requires OS '${requirement.osVersion}', but this scope has no OS release."
      else if semver.matches requirement.osVersion osRelease.version
      then true
      else throw "Package '${requirement.owner}' requires OS '${requirement.osVersion}', but the selected OS is '${osRelease.name}' release '${osRelease.version}'.")
    requirements;
in {inherit requirements checkSeeds osRequirements checkOsRequirements;}
