# Checks actual charged-inode closure independently of worker or lease release.
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
    } "project-census-image" ''
      cd crates
      cargo build --frozen --offline -p terrane-linux --no-default-features \
        --features surface-fuse --example project_census_fixture \
        --message-format=json > "$out/build.jsonl"
      rustc --print target-libdir > "$TMPDIR/structural-target-libdir"
      python3 ../tests/terrane/project_census_image.py
    '';
  native = testing.mkVMTest {
    name = "terrane-project-census-ext4";
    memory = 512;
    timeout = 60;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-project-census.XXXXXXXX)
      mkdir "$fixture_root/ext4"
      truncate -s 128M "$fixture_root/disk.img"
      mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota "$fixture_root/disk.img"
      mount -t ext4 -o loop,prjquota "$fixture_root/disk.img" "$fixture_root/ext4"
      trap 'umount "$fixture_root/ext4"; rm -rf -- "$fixture_root"' EXIT
      mkdir "$fixture_root/ext4/project"
      (cd ${image} && sha256sum --check elf-sha256sum)
      timeout --signal=TERM --kill-after=5 30 \
        ${image}/bin/project-census-fixture "$fixture_root/ext4/project"
      (cd ${image} && sha256sum --check elf-sha256sum)
      printf '%s\n' 'PASS: actual ext4 excluded-inode project census'
    '';
  };
in {
  inherit image native;
}
