##! Compatibility adapter for package-owned native storage topology.
{
  config,
  lib,
  pkgs,
  ...
}: let
  zfsState = config.aos.boot.storage.backend == "zfs-zvol";
in {
  config = lib.mkIf (!zfsState) {
    environment.systemPackages = [pkgs.mdadm pkgs.xfsprogs];
    environment.etc."mdadm.conf".source = "${pkgs.mdadm}/etc/mdadm.conf";
    aos.boot.initrd.extraPackages = [pkgs.mdadm pkgs.xfsprogs];
    aos.boot.initrd.modules = ["raid0" "raid1" "raid10" "raid456" "xfs"];
  };
}
