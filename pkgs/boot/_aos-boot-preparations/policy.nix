##! Derives stage prerequisites from the retained authored boot policy.
{
  config,
  lib,
  ...
}: {
  config.aos.boot.substrateServices = {
    enable = lib.mkDefault (config.aos.boot.stage == "initrd");
    handoffEnabled = lib.mkDefault config.aos.boot.initrd.abilityHandoff.enable;
    verityEnabled = lib.mkDefault config.aos.security.verity.enable;
    zfsEnabled = lib.mkDefault (config.aos.boot.storage.backend == "zfs-zvol");
    zfsPool = lib.mkDefault config.aos.boot.storage.zfs.poolName;
    recoveryEnabled = lib.mkDefault config.aos.boot.recovery.enable;
    recoveryAbi = lib.mkDefault config.aos.boot.recovery.abi;
    espDevice = lib.mkDefault config.aos.filesystems.espDevice;
  };
}
