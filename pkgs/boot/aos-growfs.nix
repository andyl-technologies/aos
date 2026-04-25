##! aos-growfs — first-boot ext4 resize for root-a after ignition-disks
##!
##! The ignition config resizes the root-a **partition** (e.g. from
##! ~3 GiB in the shipped image to 16 GiB), but ignition has no
##! filesystem-resize primitive. Without this service the user sees
##! a 16 GiB partition with a 3 GiB filesystem inside and 13 GiB
##! unused.
##!
##! Runs as an initrd oneshot after ignition-disks.service (which did
##! the partition resize) and before sysroot.mount (so the filesystem
##! is still unmounted and offline resize2fs works cleanly).
{
  mkDerivation,
  bash,
  coreutils,
  e2fsprogs,
}:
mkDerivation {
  pname = "aos-growfs";
  version = "0";
  src = null;

  runtimeDeps = [
    bash
    coreutils
    e2fsprogs
  ];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin

        cat > $out/bin/aos-growfs << 'SCRIPT'
        #!${bash}/bin/bash
        set -eu
        dev=/dev/disk/by-partlabel/root-a
        if [ ! -e "$dev" ]; then
            echo "aos-growfs: $dev not found, skipping" >&2
            exit 0
        fi
        # -p auto-fixes safe errors; exit 1 means "fixed, not fatal".
        ${e2fsprogs}/sbin/e2fsck -f -p "$dev" || true
        ${e2fsprogs}/sbin/resize2fs "$dev"
        SCRIPT
        chmod +x $out/bin/aos-growfs
      '';
    }
  ];

  meta = {
    description = "First-boot ext4 resize for the root-a partition";
  };
}
