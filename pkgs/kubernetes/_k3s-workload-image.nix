##! Builds the source-based workload image used by K3s regression fleets.
{
  pkgs,
  lib,
}: let
  oci = pkgs.ociTools;
  platform = {
    os = "linux";
    architecture =
      if pkgs.stdenv.hostPlatform.isAarch64
      then "arm64"
      else if pkgs.stdenv.hostPlatform.isx86_64
      then "amd64"
      else throw "K3s workload requires a supported Linux architecture";
  };
  payload = oci.mkClosureLayer {
    roots = [pkgs.coreutils];
    pname = "k3s-workload-payload";
  };
  metadata = oci.mkRootMetadataLayer {
    storeLayers = [payload];
    directories = map (path: {inherit path;}) ["/dev" "/proc" "/sys" "/tmp" "/work"];
    pname = "k3s-workload-metadata";
  };
  runtimeAudit = lib.build.runtimeClosureAudit {
    inherit pkgs;
    name = "k3s-workload";
    roots = [pkgs.coreutils];
    maxClosureMiB = 256;
    maxDevelopmentPayloadMiB = 1;
  };
  deploymentArtifact = oci.mkDeploymentArtifact {
    pname = "k3s-workload-deployment";
    inherit pkgs platform;
    scope = ["container" "k3s-workload"];
    packages = [pkgs.coreutils];
  };
in
  oci.mkImageLayout {
    pname = "k3s-workload-image";
    layers = [payload metadata];
    inherit runtimeAudit deploymentArtifact;
    referenceName = "aos.invalid/qualification:fixture";
    config = {
      entrypoint = ["${pkgs.coreutils}/bin/printf"];
      cmd = ["k3s-workload-passed\n"];
      workingDir = "/work";
    };
  }
