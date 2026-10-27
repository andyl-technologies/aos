# Measures real fs-verity before mapping; this component does not mount FUSE.
{
  pkgs,
  lib,
  sourceGateWithInputs,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  image =
    sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    } "structural-mapping-image" ''
      cd crates
      cargo build --frozen --offline -p terrane-linux --no-default-features \
        --features surface-fuse --example structural_index_fixture \
        --message-format=json > "$out/build.jsonl"
      rustc --print target-libdir > "$TMPDIR/structural-target-libdir"
      python3 ../tests/terrane/structural_mapping_image.py
    '';
  native = testing.mkVMTest {
    name = "terrane-structural-mapping-ext4";
    memory = 512;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs pkgs.python3];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-structural-mapping.XXXXXXXX)
      chmod 0711 "$fixture_root"
      mkdir "$fixture_root/ext4"
      truncate -s 128M "$fixture_root/disk.img"
      mkfs.ext4 -F -b 4096 -O verity "$fixture_root/disk.img"
      mount -t ext4 -o loop "$fixture_root/disk.img" "$fixture_root/ext4"
      trap 'umount "$fixture_root/ext4"; rm -rf -- "$fixture_root"' EXIT
      chown 840:840 "$fixture_root/ext4"
      chmod 0700 "$fixture_root/ext4"
      (cd ${image} && sha256sum --check elf-sha256sum)
      setpriv --reuid=840 --regid=840 --clear-groups --bounding-set=-all \
        --inh-caps=-all --ambient-caps=-all --no-new-privs \
        timeout --signal=TERM --kill-after=5 30 \
        ${image}/bin/structural-index-fixture "$fixture_root/ext4"
      (cd ${image} && sha256sum --check elf-sha256sum)
      printf '%s\n' 'PASS: sealed structural mapping on ext4 as UID 840 without capabilities'
    '';
  };
in {
  inherit image native;
}
