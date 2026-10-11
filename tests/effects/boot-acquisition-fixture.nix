# Developer projection; retained tool overrides must be source-built AOS roots.
{
  stateRoot,
  nixPackage ? null,
  checkerPackage ? null,
}: let
  aos = import ../.. {};
  toolOverrides =
    aos.lib.optionalAttrs (nixPackage != null) {nix = builtins.storePath nixPackage;}
    // aos.lib.optionalAttrs (checkerPackage != null) {
      aos-deployment-check = builtins.storePath checkerPackage;
    };
  pkgs =
    aos.pkgs
    // toolOverrides
    // {
      buildPackages = aos.pkgs.buildPackages // toolOverrides;
    };
  fixture = import ./boot-metadata-fixture.nix {
    inherit pkgs;
    inherit (aos) lib;
    stateDirectory = "${stateRoot}/bootstrap-state";
    acquiredStateDirectory = "${stateRoot}/acquired-state";
  };
  packages =
    {boot-acquired-fixture = fixture.acquiredPackage;}
    // builtins.listToAttrs (map (name: {
      inherit name;
      value = pkgs.${name};
    }) ["bash" "coreutils" "jq" "oniguruma"]);
  policy = import ../../pkgs/_target-policy.nix {
    inherit packages;
    inherit (aos) lib;
    releasePlatforms = ["x86_64-linux"];
  };
  closureInfo = aos.lib.build.closureInfo {inherit pkgs;};
in {
  inherit fixture;
  fixturePath = toString fixture;
  inputs = closureInfo {rootPaths = [fixture];};
  publicationInputs = closureInfo {
    rootPaths = [fixture.acquiredPackage fixture.acquiredPackage.deploymentArtifact fixture.acquiredPackage.documentationArtifact];
  };
  releasePackageDerivations = policy.releaseDerivations {
    inherit packages;
    system = "x86_64-linux";
    names = builtins.attrNames packages;
  };
}
