##! Configures package-owned typed metadata provisioning abilities.
{pkgs, ...}: {
  config.aos.boot.initrd.packageRoots = [
    pkgs.aos-metadata-provider
    pkgs.aos-nix-store-provider
    pkgs.nix
  ];
}
