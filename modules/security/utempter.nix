##! Selects the package-owned privileged terminal accounting helper module.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.libutempter];
}
