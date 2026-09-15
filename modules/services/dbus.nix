##! Selects the package-owned D-Bus system bus module for static systems.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.dbus];
}
