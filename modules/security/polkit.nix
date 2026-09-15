##! Selects the package-owned polkit feature module.
{pkgs, ...}: {
  config.environment.systemPackages = [pkgs.polkit];
}
