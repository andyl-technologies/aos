##! Bootable base with package management and a local shell.
{
  lib,
  pkgs,
  ...
}: let
  portableShellPackages = [
    pkgs.bash
    pkgs.coreutils
    pkgs.findutils
    pkgs.grep
    pkgs.sed
    pkgs.gawk
  ];
in {
  imports = [./_ability-providers.nix];

  # Admit portable host policy without installing its unused package output.
  # Active policy effects retain the exact programs and data they consume.
  aos.packages = {
    aos-host-policy = {
      package = pkgs.aos-host-policy;
      enable = true;
    };
    aos-ebpf-lsm-policy = {
      package = pkgs.aos-ebpf-lsm-policy;
      enable = true;
    };
    audit = {
      package = pkgs.audit;
      enable = true;
    };
    nftables = {
      package = pkgs.nftables;
      enable = true;
    };
    aos-network-ruleset-provider = {
      package = pkgs.aos-network-ruleset-provider;
      enable = true;
    };
    dbus = {
      package = pkgs.dbus;
      bundle = true;
    };
  };

  aos.activation.stages.host.configurationBuilders = [
    (import ../pkgs/system/_aos-host-policy/build-baseline.nix {inherit lib pkgs;})
  ];
  aos.activation.stages.initrd.configuration = ["${pkgs.aos-host-policy.module}/baseline/initrd.nix"];

  # Optional daemons and workload tools are selected by host policy or APM.
  # APM, the kernel, system manager and boot storage add their own core roots.
  environment.systemPackages = portableShellPackages ++ [pkgs.glibc-tools pkgs.util-linux pkgs.kmod pkgs.e2fsprogs pkgs.less];
  aos.containers.systemPackageSlice = portableShellPackages;
}
