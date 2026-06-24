{
  lib,
  mkDerivation,
  k3s,
  containerd,
  runc,
  cni-plugins,
  iptables,
  ipset,
  conntrack-tools,
  socat,
  ethtool,
  iproute2,
  util-linux,
  kmod,
  coreutils,
  writeShellScriptBin,
}: let
  mkK3sExposePackage = import ./_k3s-expose-package.nix {
    inherit
      lib
      mkDerivation
      k3s
      containerd
      runc
      cni-plugins
      iptables
      ipset
      conntrack-tools
      socat
      ethtool
      iproute2
      util-linux
      kmod
      coreutils
      writeShellScriptBin
      ;
  };
in
  mkK3sExposePackage {
    pname = "k3s-control-plane";
    description = "Lightweight Kubernetes (control plane, no agent)";
    command = "server --disable-agent";
    requiredEnv = ["K3S_TOKEN"];
    stateDirectories = ["rancher/k3s"];
    hostPaths = [
      {
        path = "/var/lib/rancher";
        mode = "rw";
      }
      {
        path = "/etc/rancher/k3s";
        mode = "rw";
      }
      {
        path = "/etc/rancher/node";
        mode = "rw";
      }
      {
        path = "/lib/modules";
        mode = "read-only";
      }
    ];
    firewall = {
      allowedTCP = [6443];
    };
  }
