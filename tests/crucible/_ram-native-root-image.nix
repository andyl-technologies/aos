# Immutable blank backing image for the initrd-based native RAM workloads.
{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-native-ram-root-image";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.e2fsprogs];
  phases = [
    {
      name = "build-immutable-native-root";
      script = ''
        set -eu
        export E2FSPROGS_FAKE_TIME=1
        mkdir -p "$out"
        ${pkgs.coreutils}/bin/truncate -s 8M "$out/root.ext4"
        ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F \
          -U 3a6d7ab1-2b63-4b95-87e7-6bdbb6e8c104 \
          -E hash_seed=3a6d7ab1-2b63-4b95-87e7-6bdbb6e8c104,lazy_itable_init=0,lazy_journal_init=0 \
          "$out/root.ext4"
        ${pkgs.e2fsprogs}/sbin/e2fsck -fn "$out/root.ext4"
        chmod 0444 "$out/root.ext4"
      '';
    }
  ];
}
