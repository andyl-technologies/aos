##! Uses the direct-kernel test disk contract in every native boot scope.
{
  lib,
  options,
  ...
}: {
  aos.filesystems = lib.optionalAttrs (options.aos.filesystems ? rootFsType) {
    rootFsType = lib.mkForce "ext4";
  };
  aos.security.verity.enable = lib.mkForce false;
}
