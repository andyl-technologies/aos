##! Selects the package-owned Libvirt service cohort.
{
  config,
  lib,
  pkgs,
  ...
}: {
  config = lib.mkMerge [
    {
      environment.systemPackages = [pkgs.libvirt pkgs.qemu];
    }
    (lib.mkIf config.aos.services.libvirt.enable {
      environment.etc."libvirt".source = "${pkgs.libvirt}/etc/libvirt";
      aos.security.polkit.enable = true;

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
    })
  ];
}
