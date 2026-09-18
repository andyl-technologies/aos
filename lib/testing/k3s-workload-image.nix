##! Builds the source-based workload image used by K3s regression fleets.
{
  pkgs,
  lib,
}: let
  oci = import ../build/oci {
    inherit lib;
    inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
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
  runtimeAudit = import ../build/runtime-closure-audit.nix {
    inherit pkgs lib;
    name = "k3s-workload";
    roots = [pkgs.coreutils];
    maxClosureMiB = 256;
    maxDevelopmentPayloadMiB = 1;
  };
in
  oci.mkImageLayout {
    pname = "k3s-workload-image";
    layers = [payload metadata];
    inherit runtimeAudit;
    platform = {
      os = "linux";
      architecture =
        if pkgs.stdenv.hostPlatform.isAarch64
        then "arm64"
        else if pkgs.stdenv.hostPlatform.isx86_64
        then "amd64"
        else throw "K3s workload requires a supported Linux architecture";
    };
    referenceName = "aos.invalid/qualification:fixture";
    config = {
      entrypoint = ["${pkgs.coreutils}/bin/printf"];
      cmd = ["k3s-workload-passed\n"];
      workingDir = "/work";
    };
  }
