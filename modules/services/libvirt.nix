##! modules/services/libvirt.nix — Virtual machine management service
##!
##! Enables Libvirt's monolithic system daemon with socket activation, QEMU
##! isolation accounts, packaged policy, and persistent runtime directories.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.libvirt;
in {
  options.aos.services.libvirt = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run Libvirt with the QEMU virtualization driver.";
    };

    allowedUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Users allowed to access the read-write Libvirt socket.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [pkgs.libvirt pkgs.qemu];
    environment.etc."libvirt".source = "${pkgs.libvirt}/etc/libvirt";
    environment.etc."tmpfiles.d/aos-libvirt.conf".text = ''
      d /run/libvirt 0755 root root -
      d /var/cache/libvirt 0755 root root -
      d /var/lib/libvirt 0755 root root -
      d /var/lib/libvirt/boot 0711 root root -
      d /var/lib/libvirt/dnsmasq 0755 root root -
      d /var/lib/libvirt/images 0711 root root -
      d /var/lib/libvirt/qemu 0750 libvirt-qemu libvirt-qemu -
      d /var/lib/libvirt/swtpm 0710 libvirt-qemu libvirt-qemu -
      d /var/log/libvirt 0755 root root -
      d /var/log/libvirt/qemu 0750 libvirt-qemu libvirt-qemu -
    '';

    aos.security.polkit.enable = true;
    aos.services.dbus.packages = [pkgs.libvirt];

    aos.users.users.libvirt-qemu = {
      uid = 64054;
      group = "libvirt-qemu";
      home = "/var/lib/libvirt";
      shell = "/sbin/nologin";
      description = "Libvirt QEMU virtual machine";
      extraGroups = ["kvm"];
    };
    aos.users.groups.libvirt-qemu = {
      gid = 64054;
      members = [];
    };
    aos.users.groups.libvirt = {
      gid = 64055;
      members = cfg.allowedUsers;
    };

    systemd.packages = [pkgs.libvirt];
    systemd.services.libvirtd = {
      overrideStrategy = "asDropin";
      wantedBy = ["multi-user.target"];
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      # The network driver selects its firewall backend by searching PATH at
      # daemon startup. Keep the complete helper set visible to all drivers;
      # package runtime dependencies retain the tools in the closure but do
      # not add their bin and sbin directories to a systemd service's PATH.
      path = [
        pkgs.bridge-utils
        pkgs.coreutils
        pkgs.dbus
        pkgs.dnsmasq
        pkgs.iproute2
        pkgs.iptables
        pkgs.nftables
        pkgs.numactl
        pkgs.numad
        pkgs.parted
        pkgs.passt
        pkgs.pm-utils
        pkgs.qemu
        pkgs.swtpm
        pkgs.systemd
        pkgs.util-linux
        pkgs.zfs
      ];
      serviceConfig.ExecReload = [
        ""
        "${pkgs.coreutils}/bin/kill -HUP $MAINPID"
      ];
    };
    systemd.sockets.libvirtd = {
      overrideStrategy = "asDropin";
      wantedBy = ["sockets.target"];
      socketConfig = {
        SocketMode = "0660";
        SocketGroup = "libvirt";
      };
    };
    systemd.sockets."libvirtd-ro" = {
      overrideStrategy = "asDropin";
      wantedBy = ["sockets.target"];
      socketConfig = {
        SocketMode = "0660";
        SocketGroup = "libvirt";
      };
    };
    systemd.sockets."libvirtd-admin" = {
      overrideStrategy = "asDropin";
      wantedBy = ["sockets.target"];
    };
    systemd.sockets.virtlogd = {
      overrideStrategy = "asDropin";
      wantedBy = ["sockets.target"];
    };
    systemd.sockets.virtlockd = {
      overrideStrategy = "asDropin";
      wantedBy = ["sockets.target"];
    };

    system.checks.libvirt = {
      description = "Libvirt daemon and local connection checks";
      checks = [
        {
          name = "libvirt-active";
          description = "Libvirt and its helper sockets become active";
          script = ''
            vm.wait_until_succeeds(
                "systemctl is-active --quiet libvirtd.service", timeout=60
            )
            vm.succeed("systemctl is-active --quiet virtlogd.socket")
            vm.succeed("systemctl is-active --quiet virtlockd.socket")
          '';
        }
        {
          name = "libvirt-connect";
          description = "The client connects to the local QEMU driver";
          script = ''
            vm.wait_until_succeeds(
                "virsh --connect qemu:///system list --all", timeout=30
            )
            vm.succeed("test -S /run/libvirt/libvirt-sock")
            vm.succeed("test $(stat -c %G /run/libvirt/libvirt-sock) = libvirt")
          '';
        }
      ];
    };
  };
}
