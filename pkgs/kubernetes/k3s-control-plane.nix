{
  lib,
  mkDerivation,
  k3s,
  aos-kubernetes-provider,
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
}:
let
  mkK3sRolePackage = import ./_k3s-role-package.nix {
    inherit
      lib
      mkDerivation
      k3s
      aos-kubernetes-provider
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
mkK3sRolePackage {
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
    target = [];
    role = "public-package";
  };
  pname = "k3s-control-plane";
  evidenceSources = [ ./k3s-control-plane.nix ];
}
