# Shared metadata contract for image assembly, including runtime recipes.
{pkgs}: {
  environment = ''
    # e2fsprogs 1.47.4 clamps imported inode times with SOURCE_DATE_EPOCH,
    # but e2fsck uses its older, separate override during shrink/grow.
    export SOURCE_DATE_EPOCH=1 E2FSCK_TIME=1
    export MKE2FS_CONFIG=${pkgs.e2fsprogs}/etc/mke2fs.conf
  '';
  command = "${pkgs.python3}/bin/python3 ${./image-metadata.py}";
  ext4Options = ''-U "$IMAGE_UUID" -E hash_seed="$IMAGE_UUID",lazy_itable_init=0,lazy_journal_init=0'';
}
