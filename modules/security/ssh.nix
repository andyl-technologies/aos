##! Selects the package-owned OpenSSH feature module.
{pkgs, ...}: {
  config.environment.systemPackages = [pkgs.openssh];
}
