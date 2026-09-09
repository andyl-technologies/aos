##! Builds digest-addressed images for every default K3s addon from AOS sources.
{
  lib,
  callPackage,
  buildPackages,
  stdenv,
  mkDerivation,
  fetchurl,
  bash,
  coreutils,
  grep,
  jq,
  iptables,
  ca-certificates,
}: let
  programs = callPackage ./_k3s-addon-programs.nix {};
  traefik = callPackage ./_k3s-traefik.nix {};
  helmPrograms = callPackage ./_k3s-helm-programs.nix {};
  entrypoints = import ./_k3s-addon-entrypoints.nix {
    inherit lib buildPackages helmPrograms;
    pkgs = {
      inherit mkDerivation fetchurl bash coreutils grep jq iptables;
    };
  };
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (buildPackages) mkDerivation coreutils findutils gzip jq tar;
  };
  architecture =
    if stdenv.hostPlatform.isAarch64
    then "arm64"
    else if stdenv.hostPlatform.isx86_64
    then "amd64"
    else throw "K3s addon images require a supported Linux architecture";

  mkAddon = {
    name,
    version,
    roots,
    entrypoint,
    env ? {},
    user ? "0:0",
    maxClosureMiB ? 512,
  }: let
    reference = "aos.invalid/k3s/${name}";
    imageRoots = lib.unique (roots ++ [ca-certificates]);
    payload = oci.mkClosureLayer {
      roots = imageRoots;
      pname = "k3s-${name}-payload";
    };
    metadata = oci.mkRootMetadataLayer {
      pname = "k3s-${name}-metadata";
      storeLayers = [payload];
      directories =
        (map (path: {inherit path;}) ["/dev" "/proc" "/sys" "/run" "/root" "/etc" "/work"])
        ++ [
          {
            path = "/tmp";
            mode = "1777";
          }
        ];
      files = [
        {
          path = "/etc/passwd";
          text = "root:x:0:0:root:/root:\nk3s:x:1000:1000:K3s:/tmp:\nnobody:x:65532:65532:nobody:/tmp:\n";
        }
        {
          path = "/etc/group";
          text = "root:x:0:\nk3s:x:1000:\nnobody:x:65532:\n";
        }
      ];
      symlinks = [
        {
          path = "/etc/ssl/certs/ca-certificates.crt";
          target = "${ca-certificates}/etc/ssl/certs/ca-certificates.crt";
        }
      ];
    };
    runtimeAudit = import ../../lib/build/runtime-closure-audit.nix {
      inherit lib name maxClosureMiB;
      pkgs = buildPackages;
      roots = imageRoots;
      maxDevelopmentPayloadMiB = 1;
    };
  in {
    inherit reference;
    evidenceSources = lib.unique (lib.concatMap (root:
      if root ? passthru && root.passthru ? evidenceSources
      then root.passthru.evidenceSources
      else if !(root ? src) || root.src == null
      then []
      else if builtins.isList root.src
      then root.src
      else [root.src])
    imageRoots);
    image = oci.mkImageLayout {
      pname = "k3s-${name}-image";
      layers = [payload metadata];
      inherit runtimeAudit;
      platform = {
        os = "linux";
        inherit architecture;
      };
      referenceName = "${reference}:${version}";
      config = {
        inherit entrypoint user;
        workingDir = "/work";
        env = {SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";} // env;
      };
    };
  };
in {
  coredns = mkAddon {
    name = "coredns";
    inherit (programs.coredns) version;
    roots = [programs.coredns];
    entrypoint = ["${programs.coredns}/bin/coredns"];
    user = "65532:65532";
  };
  metrics-server = mkAddon {
    name = "metrics-server";
    inherit (programs.metrics-server) version;
    roots = [programs.metrics-server];
    entrypoint = ["${programs.metrics-server}/bin/metrics-server"];
    user = "1000:1000";
  };
  local-path-provisioner = mkAddon {
    name = "local-path-provisioner";
    inherit (programs.local-path-provisioner) version;
    roots = [programs.local-path-provisioner];
    entrypoint = ["${programs.local-path-provisioner}/bin/local-path-provisioner"];
    env.PATH = "${programs.local-path-provisioner}/bin";
  };
  local-path-helper = mkAddon {
    name = "local-path-helper";
    version = "1";
    roots = [bash coreutils];
    entrypoint = ["${bash}/bin/bash"];
    env.PATH = "${coreutils}/bin:${bash}/bin";
  };
  traefik = mkAddon {
    name = "traefik";
    inherit (traefik) version;
    roots = [traefik];
    entrypoint = ["${traefik}/bin/traefik"];
    user = "65532:65532";
  };
  helm-job = mkAddon {
    name = "helm-job";
    inherit (entrypoints.helm) version;
    roots = [entrypoints.helm helmPrograms.plugins];
    entrypoint = ["${entrypoints.helm}/bin/klipper-helm"];
    user = "1000:1000";
    maxClosureMiB = 1024;
    env = {
      HOME = "/tmp";
      HELM_PLUGINS = "${helmPrograms.plugins}/share/helm/plugins";
      HELM_CONFIG_HOME = "/tmp/helm/config";
      HELM_CACHE_HOME = "/tmp/helm/cache";
      HELM_DATA_HOME = "/tmp/helm/data";
      STABLE_REPO_URL = "https://charts.helm.sh/stable/";
      TIMEOUT = "";
    };
  };
  service-lb = mkAddon {
    name = "service-lb";
    inherit (entrypoints.loadBalancer) version;
    roots = [entrypoints.loadBalancer];
    entrypoint = ["${entrypoints.loadBalancer}/bin/klipper-lb"];
  };
}
