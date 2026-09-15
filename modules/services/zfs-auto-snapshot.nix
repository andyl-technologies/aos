##! Selects the package-owned zfstools snapshot service module.
{
  config,
  lib,
  pkgs,
  ...
}: {
  config = {
    environment.systemPackages = [pkgs.zfstools];
    aos.services.zfsAutoSnapshot.storageReadiness =
      config.aos.filesystems.zfs.readinessResources;

    assertions = lib.mkIf config.aos.services.zfsAutoSnapshot.enable [
      {
        assertion = config.aos.filesystems.zfs.enable;
        message = "aos.services.zfsAutoSnapshot requires aos.filesystems.zfs.enable";
      }
    ];
  };
}
