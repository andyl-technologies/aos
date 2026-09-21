##! Selects the package-owned zfstools snapshot service module.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.zfstools];
}
