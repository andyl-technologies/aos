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
    pname = "k3s-combined";
    role = "combined";
    description = "Lightweight Kubernetes (combined: server + agent)";
    command = "server";
    requiredEnv = [];
    firewall = {
      allowedTCP = [6443 10250];
      allowedUDP = [8472];
      forwardPolicy = "accept";
    };
  }
