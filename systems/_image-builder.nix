##! Selects the package-owned immutable systemd image builder.
{pkgs, ...}: {
  imports = [../pkgs/system/_systemd-abilities/platform/image.nix];
  environment.systemPackages = [pkgs.systemd];
}
