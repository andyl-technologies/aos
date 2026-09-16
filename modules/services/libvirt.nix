##! Selects the package-owned Libvirt service cohort.
{pkgs, ...}: {
  config.environment.systemPackages = [pkgs.libvirt pkgs.qemu];
}
