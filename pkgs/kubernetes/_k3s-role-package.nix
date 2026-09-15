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
  pkgs = {
    inherit
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
  common = import ./_k3s-common.nix { inherit lib pkgs; };
in
{
  pname,
  evidenceSources,
}:
let
  roleSpec = (import ./_k3s-config/roles.nix).${pname};
  addonRenderer = common.addonRenderer pname roleSpec.role;
  launcher = common.launcher pname roleSpec.command addonRenderer;
in
mkDerivation {
  inherit pname;
  inherit (k3s) version;
  src = null;
  runtimeDeps = common.runtimePath;

  abilities = ./_k3s-config/module.nix;

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/share/${pname}"
        ln -s ${launcher}/bin/k3s-${pname}-start "$out/bin/k3s-role-start"
        printf '%s\n' ${lib.escapeShellArg pname} > "$out/share/${pname}/payload.txt"
      '';
    }
  ];

  passthru.evidenceSources = evidenceSources ++ [
    ./_k3s-role-package.nix
    ./_k3s-common.nix
    ./_k3s-config
  ];

  meta = {
    description = roleSpec.description;
    license = "Apache-2.0";
  };

  checks =
    {
      pkgs,
      self,
      ...
    }:
    let
      buildPkgs = pkgs.buildPackages or pkgs;
      platform = pkgs.stdenv.hostPlatform;
    in
    {
      payload-consumption = import ../../lib/build/artifact-consumption-audit.nix {
        inherit pkgs lib;
        name = "${pname}-k3s-payload";
        consumer = launcher;
        consumerPath = "/bin/k3s-${pname}-start";
        provider = pkgs.k3s;
        providerPath = "/bin/k3s";
        targetPlatform = {
          system = platform.constraints.os;
          architecture = platform.constraints.cpu;
        };
        mechanism = "helper-execution";
        arguments = [
          "verify-payload"
          "${pkgs.k3s}/bin/k3s"
        ];
        expectedOutputSha256 = "sha256:${builtins.hashString "sha256" "k3s-payload-ok\n"}";
        inspector = buildPkgs.aos;
      };
    };
}
