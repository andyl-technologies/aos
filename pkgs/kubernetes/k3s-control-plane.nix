{
  lib,
  callPackage,
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
  jq,
  writeShellScriptBin,
}: let
  mkK3sExposePackage = import ./_k3s-expose-package.nix {
    pause = callPackage ./_k3s-pause-image.nix {};
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
      jq
      writeShellScriptBin
      ;
  };
in
  mkK3sExposePackage {
    pname = "k3s-control-plane";
    role = "control-plane";
    description = "Lightweight Kubernetes (control plane, no agent)";
    # Agentless servers need the worker tunnels to reach aggregated APIs and
    # admission webhooks; they have no local flannel or kube-proxy routes.
    command = "server --disable-agent --egress-selector-mode=cluster";
    requiredEnv = [];
    evidenceSources = [./k3s-control-plane.nix];
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
