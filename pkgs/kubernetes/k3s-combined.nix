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
  jq,
  writeShellScriptBin,
}:
let
  mkK3sRolePackage = import ./_k3s-role-package.nix {
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
mkK3sRolePackage {
  pname = "k3s-combined";
  evidenceSources = [ ./k3s-combined.nix ];
}
