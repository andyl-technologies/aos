# Formats and checks disposable project-quota capacity; it issues no credit.
{
  pkgs,
  imageBytes,
  projectBytes,
  projectInodes,
}: ''
  # Provision every authored project inode plus the actual immutable
  # image census. These counts are filesystem capacity, not credits.
  image_entries=$(${pkgs.findutils}/bin/find rootfs -printf . | wc -c)
  required_inodes=$((image_entries + ${toString projectInodes}))
  truncate -s ${toString imageBytes} "$out"
  ${pkgs.fakeroot}/bin/fakeroot ${pkgs.bash}/bin/bash -c '
    chown -R 0:0 rootfs
    ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota -N "$1" -d rootfs "$out"
  ' -- "$required_inodes"
  # Populate-before-publication must also reconcile project-zero usage. The
  # freshly owned image is writable here; final validation remains read-only.
  repair_status=0
  ${pkgs.e2fsprogs}/sbin/e2fsck -pf "$out" || repair_status=$?
  case "$repair_status" in
    0|1) ;;
    *) exit "$repair_status" ;;
  esac
  ${pkgs.e2fsprogs}/sbin/e2fsck -fn "$out"
  mkdir -p "$metadata"
  ${pkgs.e2fsprogs}/sbin/dumpe2fs -h "$out" > "$metadata/filesystem-header.txt"
  ${pkgs.gawk}/bin/awk -F ': *' '
    $1 == "Filesystem features" { features = $2 }
    $1 == "Free blocks" { blocks = $2 }
    $1 == "Reserved block count" { reserved = $2 }
    $1 == "Block size" { block_size = $2 }
    $1 == "Free inodes" { inodes = $2 }
    END {
      if (features !~ /(^| )quota( |$)/ || features !~ /(^| )project( |$)/ ||
          (blocks - reserved) * block_size < ${toString projectBytes} || inodes < ${toString projectInodes}) {
        print "Disposable filesystem cannot cover the authored project partition" > "/dev/stderr"
        exit 1
      }
    }
  ' "$metadata/filesystem-header.txt"
  printf '%s\n' "$image_entries" > "$metadata/immutable-entry-count"
  printf '%s\n' "$required_inodes" > "$metadata/requested-inode-count"
''
