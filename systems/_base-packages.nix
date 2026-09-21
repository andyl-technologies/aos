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
  bundledPackage = package: {
    name = package.pname;
    value = {
      inherit package;
      bundle = true;
    };
  };
in {
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
  environment.systemPackages = [
    pkgs.bash
    pkgs.coreutils
    pkgs.findutils
    pkgs.grep
    pkgs.sed
    pkgs.gawk
    pkgs.util-linux
    pkgs.kmod
    pkgs.e2fsprogs
    pkgs.less

    # These packages supply the provider and consumer modules admitted into
    # the final package-module fixed point for the current system variants.
    pkgs.aos-filesystem-provider
    pkgs.cryptsetup
    pkgs.aos-cryptsetup-provider
    pkgs.aos-storage-format-provider
    pkgs.aos-storage-provisioning-provider
    pkgs.aos-zfs-provider
    pkgs.aos-kernel-tunable-provider
    pkgs.aos-nix-store-provider
    pkgs.aos-boot-preparation-provider
    pkgs.aos-boot-preparations

    # Companion command and runtime packages without native modules.
    pkgs.docker
    pkgs.policycoreutils
    pkgs.qemu
    pkgs.dnsutils
    pkgs.getent
    pkgs.iproute2
    pkgs.iptables
    pkgs.procps-ng
  ];
}
