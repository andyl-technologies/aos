##! Selects the exact kernel package for both native boot scopes.
{
  config,
  pkgs,
  ...
}: {
  aos.kernel.packageRoot = pkgs.linux;
  environment.systemPackages = [config.aos.kernel.packageRoot];
  aos.boot.initrd.packageRoots = [config.aos.kernel.packageRoot];
}
