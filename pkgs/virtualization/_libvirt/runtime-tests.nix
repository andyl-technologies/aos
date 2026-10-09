##! Preserves local libvirt socket and connection checks.
{
  description = "Libvirt local connection checks";
  checks = [
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
}
