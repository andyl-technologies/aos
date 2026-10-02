##! Admit provider contracts without installing unused implementations.
{pkgs, ...}: let
  providers = [
    pkgs.aos-configuration-provider
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
in {
  # Selected effects retain their handlers through the native graph. Merely
  # making a contract available must not install every provider's payload.
  aos.packages = builtins.listToAttrs (map (package: {
      name = package.pname;
      value = {
        inherit package;
        enable = true;
      };
    })
    providers);
}
