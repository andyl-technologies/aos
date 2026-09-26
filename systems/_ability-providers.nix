##! Package roots for the provider implementations selected by current systems.
{pkgs, ...}: {
  environment.systemPackages = [
    pkgs.aos-filesystem-provider
    pkgs.cryptsetup
    pkgs.aos-cryptsetup-provider
    pkgs.aos-storage-format-provider
    pkgs.aos-storage-provisioning-provider
    pkgs.aos-zfs-provider
    pkgs.aos-kernel-tunable-provider
    pkgs.aos-nix-store-provider
    pkgs.aos-boot-preparation-provider
    pkgs.kmod
  ];
}
