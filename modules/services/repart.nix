##! modules/services/repart.nix — one-time host-driven storage provisioning
##!
##! Selects the retained provisioning module and handler payload for initrd
##! evaluation. The native transaction runtime owns mutation and recovery.
{
  config,
  lib,
  pkgs,
  ...
}: {
  config = lib.mkIf (config.aos.image.enable && config.aos.boot.storage.backend != "zfs-zvol") {
    aos.storageProvisioning.protectedVarContext = lib.mkIf (
      config.aos.security.selinux.protectedSandboxNetworkRoots.enable
      || config.aos.sandbox.controllerService.method46TpmFloor.required
      || config.aos.sandbox.storageBroker.method46TpmFloor.required
    ) config.aos.security.selinux.protectedSandboxNetworkRoots._varRootContext;
    environment.systemPackages = [pkgs.aos-storage-provisioning-provider];
    aos.boot.initrd.packageRoots = [pkgs.aos-storage-provisioning-provider];
  };
}
