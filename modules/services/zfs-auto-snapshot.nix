##! Selects the package-owned zfstools snapshot service module.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.zfstools];

  assertions = lib.mkIf config.aos.services.zfsAutoSnapshot.enable [
    {
      assertion = config.aos.filesystems.zfs.enable;
      message = "aos.services.zfsAutoSnapshot requires aos.filesystems.zfs.enable";
    }
  ];
}
