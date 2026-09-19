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
  abilityContract = oci.mkStaticAbilityContract {
    pname = "k3s-workload-static-abilities";
    inherit platform;
    runtimeRoots = [pkgs.coreutils];
  };
in
  oci.mkImageLayout {
    pname = "k3s-workload-image";
    layers = [payload metadata];
    inherit runtimeAudit abilityContract;
    referenceName = "aos.invalid/qualification:fixture";
    config = {
      entrypoint = ["${pkgs.coreutils}/bin/printf"];
      cmd = ["k3s-workload-passed\n"];
      workingDir = "/work";
    };
  }
