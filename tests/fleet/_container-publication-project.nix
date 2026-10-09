##! Retains genuine evaluated package inventory for an isolated fixture publisher.
{
  lib,
  pkgs,
  packages,
}: let
  system = pkgs.stdenv.hostPlatform.system;
  # APR publishes all ordinary packages declared by one source build. Retain
  # the real named output packages, including their own native metadata.
  publicationClosure = builtins.genericClosure {
    startSet =
      lib.mapAttrsToList (name: package: {
        key = name;
        inherit package;
      })
      packages;
    operator = record:
      lib.mapAttrsToList (name: definition: let
        package = packages.${name} or pkgs.${name}
        or (throw "Fixture source build declares unavailable subpackage '${name}'.");
        output = record.package.${definition.output};
      in
        if package.drvPath != record.package.drvPath || builtins.toString package != builtins.toString output
        then throw "Fixture subpackage '${name}' differs from its declared source build output."
        else {
          key = name;
          inherit package;
        })
      (record.package.outputPackages or {});
  };
  publicationPackages = builtins.listToAttrs (map (record: {
      name = record.key;
      value = record.package;
    })
    publicationClosure);
  names = builtins.attrNames publicationPackages;
  policy = import ../../pkgs/_target-policy.nix {
    inherit lib;
    packages = publicationPackages;
    releasePlatforms = [system];
  };
  inventory = policy.releaseDerivations {
    inherit system names;
    packages = publicationPackages;
  };
  # APR authenticates every output of the evaluated source build, including
  # outputs that are not separate published packages. Keep them registered in
  # the fixture store alongside their recipes and package metadata.
  retainArtifact = artifact: [artifact (builtins.unsafeDiscardOutputDependency artifact.drvPath)];
  packageArtifacts = import ../../lib/packages/artifacts.nix {};
  selectedPackages = builtins.attrValues publicationPackages;
  # Native envelopes authenticate every declared runtime dependency output,
  # including development outputs that executable closures do not reference.
  runtimeDependencies = lib.concatMap (package:
    packageArtifacts.dependencyValues (package.runtimeDeps or []))
  selectedPackages;
  sourceOutputs = lib.concatMap (package:
    map (outputName:
      if outputName == "out"
      then package
      else package.${outputName})
    (package.outputs or ["out"]))
  (selectedPackages ++ runtimeDependencies);
  # The release policy names a distinct deployment companion for each output.
  # Use its retention projection so the fixture and APR select the same roots.
  publicationRoots = policy.releaseDerivationRoots {
    inherit system names;
    packages = publicationPackages;
  };
  nativeRoots = lib.uniqueBy builtins.toString (lib.concatMap retainArtifact (sourceOutputs ++ publicationRoots));
  # Inventory locators deliberately have no string context. Restore retention
  # from their actual package roots without inventing publication metadata.
  inventoryFile = pkgs.writeTextFile {
    name = "container-publication-inventory.json";
    text = builtins.appendContext (builtins.toJSON inventory) (builtins.getContext (builtins.toJSON nativeRoots));
  };
  project = pkgs.writeTextFile {
    name = "container-publication-project";
    destination = "/default.nix";
    text = ''
      {crossSystem ? ${builtins.toJSON system}, releasePlatforms ? []}: {
        releasePackageDerivations =
          assert crossSystem == ${builtins.toJSON system};
          builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.readFile ${inventoryFile}));
      }
    '';
  };
in {
  inherit project inventory inventoryFile nativeRoots;
}
