##! Selects the package-owned OpenPubkey SSH authentication module.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.opkssh];
}
