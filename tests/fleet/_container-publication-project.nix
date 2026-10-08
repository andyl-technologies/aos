##! Retains genuine evaluated package inventory for an isolated fixture publisher.
{
  lib,
  pkgs,
  packages,
}: let
  system = pkgs.stdenv.hostPlatform.system;
  names = builtins.attrNames packages;
  policy = import ../../pkgs/_target-policy.nix {
    inherit lib packages;
    releasePlatforms = [system];
  };
  inventory = policy.releaseDerivations {
    inherit system packages names;
  };
  # Recipe paths retain source evidence without requesting every compiler or
  # sibling output that the recipe's original evaluation made available.
  nativeRoots = lib.concatMap (name: let
    package = packages.${name};
  in
    [package (builtins.unsafeDiscardOutputDependency package.drvPath) package.deploymentArtifact package.documentationArtifact]
    ++ lib.optional (package ? qualificationArtifact && package.qualificationArtifact != null) package.qualificationArtifact)
  names;
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
