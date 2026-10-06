# Disposable-kernel prerequisites and concrete artifact bindings for native RAM tests.
{
  pkgs,
  lib,
  nativeQemu,
  nativePlugin,
  guest,
  lanes,
  buildGraph,
  storageImageBytes ? 8589934592,
}: ''
  for kernel_config in ${pkgs.linux}/boot/config-*; do
    ${pkgs.grep}/bin/grep -qx 'CONFIG_USERFAULTFD=y' "$kernel_config"
    ${pkgs.grep}/bin/grep -qx 'CONFIG_CFS_BANDWIDTH=y' "$kernel_config"
    ${pkgs.grep}/bin/grep -qx 'CONFIG_QUOTA=y' "$kernel_config"
    ${pkgs.grep}/bin/grep -qx 'CONFIG_QFMT_V2=y' "$kernel_config"
    ${pkgs.grep}/bin/grep -qx 'CONFIG_QUOTACTL=y' "$kernel_config"
  done

  # This policy applies only to this disposable outer VM. The invoking
  # builder's kernel policy and namespaces are never modified.
  test -e /proc/sys/vm/unprivileged_userfaultfd
  echo 1 > /proc/sys/vm/unprivileged_userfaultfd
  test "$(cat /proc/sys/vm/unprivileged_userfaultfd)" = 1
  mkdir -p /sys/fs/cgroup
  if ! ${pkgs.grep}/bin/grep -q ' /sys/fs/cgroup cgroup2 ' /proc/mounts; then
    ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
  fi
  echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
  mkdir /sys/fs/cgroup/paging
  echo '+cpu +memory +pids' > /sys/fs/cgroup/paging/cgroup.subtree_control

  ${pkgs.coreutils}/bin/truncate -s ${toString storageImageBytes} /var/paging-storage.img
  ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /var/paging-storage.img
  mkdir -p /var/paging-storage
  ${pkgs.util-linux}/bin/mount -o loop,prjquota /var/paging-storage.img /var/paging-storage
  for lane in ${lib.concatStringsSep " " lanes}; do
    mkdir "/sys/fs/cgroup/paging/$lane"
    echo '+cpu +memory +pids' > "/sys/fs/cgroup/paging/$lane/cgroup.subtree_control"
    mkdir -m 700 "/var/paging-storage/$lane"
  done
  ${pkgs.coreutils}/bin/truncate -s 8M /var/paging-root.ext4
  ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F /var/paging-root.ext4
  chmod 644 /var/paging-root.ext4

  mkdir -m 700 /var/paging-history
  export CRUCIBLE_PAGING_HISTORY=/var/paging-history
  export CRUCIBLE_PAGING_BUILD_GRAPH=${buildGraph}
  export CRUCIBLE_PAGING_QEMU=${nativeQemu}/bin/qemu-system-x86_64
  export CRUCIBLE_PAGING_PLUGIN=${nativePlugin}/lib/libcrucible_qemu_plugin.so
  for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
    export CRUCIBLE_PAGING_KERNEL="$kernel"
  done
  export CRUCIBLE_PAGING_INITRD=${guest}/initrd.img
  export CRUCIBLE_PAGING_ROOT=/var/paging-root.ext4
  export CRUCIBLE_PAGING_CGROUP=/sys/fs/cgroup/paging
  export CRUCIBLE_PAGING_STORAGE=/var/paging-storage
''
