##! Base payload and provider selection for current system variants.
{
  lib,
  pkgs,
  ...
}: let
  hostPackages = [
    pkgs.aos
    pkgs.aos-ebpf-lsm-policy
    pkgs.aos-ebpf-net-policy
    pkgs.aos-hub
    pkgs.aos-network-ruleset-provider
    pkgs.audit
    pkgs.bind
    pkgs.chrony
    pkgs.dbus
    pkgs.dnsmasq
    pkgs.docker-engine
    pkgs.libutempter
    pkgs.libvirt
    pkgs.nftables
    pkgs.openssh
    pkgs.opkssh
    pkgs.polkit
    pkgs.refpolicy
    pkgs.sudo
    pkgs.tailscale
    pkgs.zfstools
    pkgs.zram-generator
  ];
  portableShellPackages = [
    pkgs.bash
    pkgs.coreutils
    pkgs.findutils
    pkgs.grep
    pkgs.sed
    pkgs.gawk
  ];
  hostUtilities = [
    pkgs.util-linux
    pkgs.e2fsprogs
    pkgs.less
    pkgs.docker
    pkgs.policycoreutils
    pkgs.qemu
    pkgs.dnsutils
    pkgs.getent
    pkgs.iproute2
    pkgs.iptables
    pkgs.procps-ng
  ];
  bundledPackage = package: {
    name = package.pname;
    value = {
      inherit package;
      bundle = true;
    };
  };
in {
  imports = [./_ability-providers.nix];

  aos.packages =
    builtins.listToAttrs (builtins.map bundledPackage hostPackages)
    // {
      smartmontools = {
        package = pkgs.smartmontools;
        enable = true;
      };
    };

  aos.security.ebpfLsm.enable = lib.mkDefault true;

  # Keep the interactive image baseline explicit at the system-composition
  # boundary. Feature modules use absolute package paths, so selecting a
  # feature does not silently expand the login PATH.
  environment.systemPackages = portableShellPackages ++ hostUtilities;
  aos.containers.systemPackageSlice = portableShellPackages;
}
