##! modules/services/repart.nix — one-time host-driven storage provisioning
##!
##! Selects the package-owned checked block-storage provider for the initrd
##! fixed point. The resolved stage executor is the only mutation path; its
##! retained ResourceReference and result evidence carry provisioning state.
{
  config,
  lib,
  pkgs,
  ...
}: {
  config = lib.mkIf (config.aos.boot.storage.backend != "zfs-zvol") {
    environment.systemPackages = [pkgs.aos-storage-provisioning-provider];
    aos.boot.initrd.extraPackages = [pkgs.aos-storage-provisioning-provider];
    aos.abilities.stages.initrd.packages = [pkgs.aos-storage-provisioning-provider];
  };
}
