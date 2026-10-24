# Exercises actual Rust transport ownership on the AOS kernel in an isolated VM.
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
    } "fuse-connection-image" ''
      cd crates
      cargo build --frozen --offline -p terrane-linux --no-default-features \
        --features native-test-fixtures,surface-fuse --example fuse_connection_fixture \
        --message-format=json > "$out/build.jsonl"
      rustc --print target-libdir > "$TMPDIR/structural-target-libdir"
      python3 ../tests/terrane/fuse_connection_image.py
      mkdir -p "$out/share"
      cp ../tests/terrane/fuse_connection_vm.py "$out/share/fuse_connection_vm.py"
    '';
  native = testing.mkVMTest {
    name = "terrane-fuse-connection";
    memory = 512;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs pkgs.python3];
    testScript = ''
      set -euo pipefail
      umask 077
      unset LD_LIBRARY_PATH
      mount -o remount,rw /
      fixture_root=$(mktemp -d /var/terrane-fuse-connection.XXXXXXXX)
      backing_mounted=false
      trap 'if "$backing_mounted"; then umount "$fixture_root/backing"; fi; rm -rf -- "$fixture_root"' EXIT
      mkdir "$fixture_root/backing"
      truncate -s 64M "$fixture_root/backing.img"
      mkfs.ext4 -F -b 4096 -O verity "$fixture_root/backing.img"
      mount -t ext4 -o loop "$fixture_root/backing.img" "$fixture_root/backing"
      backing_mounted=true
      if [ ! -e /dev/fuse ]; then
        mknod /dev/fuse c 10 229
      fi
      chmod 0666 /dev/fuse
      (cd ${image} && sha256sum --check elf-sha256sum)
      timeout --signal=TERM --kill-after=5 30 \
        ${pkgs.python3}/bin/python3 ${image}/share/fuse_connection_vm.py \
        ${image}/bin/fuse-connection-fixture "$fixture_root"
      (cd ${image} && sha256sum --check elf-sha256sum)
      printf '%s\n' 'PASS: actual confined FUSE transport, final descriptor close and cancellation'
    '';
  };
in {
  inherit image native;
}
