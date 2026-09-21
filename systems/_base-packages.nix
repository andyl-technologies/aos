##! Base payload and provider selection for current system variants.
{pkgs, ...}: {
  aos.packages.smartmontools = {
    package = pkgs.smartmontools;
    enable = true;
  };

  # Keep the interactive image baseline explicit at the system-composition
  # boundary. Feature modules use absolute package paths, so selecting a
  # feature does not silently expand the login PATH.
  environment.systemPackages = [
    pkgs.bash
    pkgs.coreutils
    pkgs.findutils
    pkgs.grep
    pkgs.sed
    pkgs.gawk
    pkgs.util-linux
    pkgs.kmod
    pkgs.e2fsprogs
    pkgs.less

    # These packages supply the provider and consumer modules admitted into
    # the final package-module fixed point for the current system variants.
    pkgs.aos-filesystem-provider
    pkgs.cryptsetup
    pkgs.aos-cryptsetup-provider
    pkgs.aos-storage-format-provider
    pkgs.aos-storage-provisioning-provider
    pkgs.aos-zfs-provider
    pkgs.aos-kernel-tunable-provider
    pkgs.aos-nix-store-provider
    pkgs.aos-boot-preparation-provider
    pkgs.aos-boot-preparations
  ];
}
