##! Uses the direct-kernel test disk contract in every native boot scope.
{lib, ...}: {
  aos.filesystems.rootFsType = lib.mkForce "ext4";
  aos.security.verity.enable = lib.mkForce false;
}
