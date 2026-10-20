##! Pins native configuration-lower tools for compilation and its test targets.
{
  erofs-utils,
  util-linux,
  packageRuntime,
}: {
  AOS_MKFS_EROFS = "${erofs-utils}/bin/mkfs.erofs";
  AOS_FSCK_EROFS = "${erofs-utils}/bin/fsck.erofs";
  AOS_MOUNT = "${util-linux}/bin/mount";
  AOS_UMOUNT = "${util-linux}/bin/umount";
  AOS_PACKAGE_RUNTIME = "${packageRuntime}/bin/aos-package-runtime";
}
