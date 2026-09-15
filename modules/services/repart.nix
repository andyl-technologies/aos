##! modules/services/repart.nix — one-time host-driven storage provisioning
##!
##! Selects the package-owned repart command and typed initrd lifecycle for the
##! block-storage backend. The package declaration owns its exact ordering
##! against authenticated plan evaluation, device readiness, and persistent
##! state consumers.
{
  config,
  lib,
  pkgs,
  ...
}: {
  config = lib.mkIf (config.aos.boot.storage.backend != "zfs-zvol") {
    environment.systemPackages = [pkgs.aos-storage-provisioning-provider];
    aos.boot.initrd.extraPackages = [pkgs.aos-storage-provisioning-provider];
    aos.abilities.stages.initrd = {
      packages = [pkgs.aos-storage-provisioning-provider pkgs.systemd];
      intent = [
        {aos.storage.provisioningService.enable = true;}
      ];
    };
  };
}
