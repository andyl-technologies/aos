# Exercises actual Unix process credentials and sealed descriptor passing.
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
    } "worker-channel-image" ''
      cd crates
      cargo build --frozen --offline -p terrane-linux --no-default-features \
        --features native-test-fixtures,surface-fuse --example worker_channel_fixture \
        --message-format=json > "$out/build.jsonl"
      rustc --print target-libdir > "$TMPDIR/structural-target-libdir"
      python3 ../tests/terrane/worker_channel_image.py
    '';
  native = testing.mkVMTest {
    name = "terrane-worker-channel-ext4";
    memory = 512;
    timeout = 60;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-worker-channel.XXXXXXXX)
      mkdir "$fixture_root/ext4"
      truncate -s 128M "$fixture_root/disk.img"
      mkfs.ext4 -F -b 4096 -O verity "$fixture_root/disk.img"
      mount -t ext4 -o loop "$fixture_root/disk.img" "$fixture_root/ext4"
      trap 'umount "$fixture_root/ext4"; rm -rf -- "$fixture_root"' EXIT
      mkdir "$fixture_root/ext4/private"
      chmod 0700 "$fixture_root/ext4/private"
      (cd ${image} && sha256sum --check elf-sha256sum)
      timeout --signal=TERM --kill-after=5 30 \
        ${image}/bin/worker-channel-fixture "$fixture_root/ext4/private" \
        ${pkgs.util-linux}/bin/setpriv
      (cd ${image} && sha256sum --check elf-sha256sum)
      printf '%s\n' 'PASS: native worker credentials, incarnation and original sealed descriptor transport'
    '';
  };
in {
  inherit image native;
}
