##! Selects the package-owned SELinux policy feature module.
{pkgs, ...}: {
  config.environment.systemPackages = [pkgs.refpolicy pkgs.policycoreutils];
}
