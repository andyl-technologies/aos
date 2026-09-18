##! Builds the pod sandbox image retained by the K3s agent packages.
{
  mkDerivation,
  fetchurl,
  glibc,
  buildPackages,
  stdenv,
  lib,
}: let
  kubernetes = import ./_source.nix {inherit fetchurl;};
  buildPkgs = buildPackages;
  reference = "aos.invalid/k3s/pause";
  pause = mkDerivation {
    pname = "k3s-pause";
    inherit (kubernetes) version src;
    buildDeps = [];
    runtimeDeps = [glibc];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd kubernetes-${kubernetes.version}
        '';
      }
      {
        name = "build";
        script = ''
          "$CC" $CFLAGS -DVERSION=${kubernetes.version} \
            build/pause/linux/pause.c $LDFLAGS -o pause
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/licenses/k3s-pause"
          install -m 0755 pause "$out/bin/pause"
          cp LICENSE "$out/share/licenses/k3s-pause/"
        '';
      }
    ];
    meta = {
      description = "Kubernetes pod sandbox process built from the pinned Kubernetes source";
      license = "Apache-2.0";
    };
  };
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (buildPkgs) mkDerivation coreutils findutils gzip jq tar;
  };
  payload = oci.mkClosureLayer {
    roots = [pause];
    pname = "k3s-pause-payload";
  };
  metadata = oci.mkRootMetadataLayer {
    storeLayers = [payload];
    directories = map (path: {inherit path;}) ["/dev" "/proc" "/sys"];
    pname = "k3s-pause-metadata";
  };
  runtimeAudit = import ../../lib/build/runtime-closure-audit.nix {
    inherit lib;
    pkgs = buildPkgs;
    name = "k3s-pause";
    roots = [pause];
    maxClosureMiB = 128;
    maxDevelopmentPayloadMiB = 1;
  };
in {
  inherit reference;
  image = oci.mkImageLayout {
    pname = "k3s-pause-image";
    layers = [payload metadata];
    inherit runtimeAudit;
    platform = {
      os = "linux";
      architecture =
        if stdenv.hostPlatform.isAarch64
        then "arm64"
        else if stdenv.hostPlatform.isx86_64
        then "amd64"
        else throw "K3s pod sandboxes require a supported Linux architecture";
    };
    referenceName = "${reference}:${kubernetes.version}";
    config = {
      entrypoint = ["${pause}/bin/pause"];
      user = "65535:65535";
    };
  };
}
