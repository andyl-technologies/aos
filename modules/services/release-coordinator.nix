##! Selects the package-owned release maintenance service module.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.aos];
}
