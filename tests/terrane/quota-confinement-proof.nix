# Dedicated kernel evidence, outside gate discovery. This does not qualify the
# complete cache or host-quota-exact gate; the owning gate composes it explicitly.
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
    } "quota-confinement-proof-image" ''
      cd crates
      cargo build --frozen --offline -p terrane-linux --features tokio \
        --example quota_confinement_fixture --message-format=json \
        > "$TMPDIR/confinement-artifacts.jsonl"
      cargo metadata --frozen --offline --no-deps --format-version=1 \
        > "$TMPDIR/confinement-packages.json"
      rustc --print target-libdir > "$TMPDIR/confinement-target-libdir"
      python3 ${../../crates/terrane/linux/terrane-linux/src/quota_confinement/proof_image.py} ${./.}
    '';
  native = testing.mkVMTest {
    name = "terrane-quota-confinement-ext4";
    memory = 1024;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      set -eu
      cd ${image}
      sha256sum -c share/checksums.sha256
      mount -o remount,rw /
      mkdir -p /var/lib/terrane-confinement-proof /mnt/terrane-confinement
      truncate -s 96M /var/lib/terrane-confinement-proof/quota.img
      # The native verity profile uses 4096-byte blocks; small ext4 images
      # otherwise default to blocks too small for that profile.
      mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota /var/lib/terrane-confinement-proof/quota.img
      mount -t ext4 -o loop,prjquota /var/lib/terrane-confinement-proof/quota.img /mnt/terrane-confinement
      trap 'umount /mnt/terrane-confinement; rm -f /var/lib/terrane-confinement-proof/quota.img; rmdir /mnt/terrane-confinement /var/lib/terrane-confinement-proof' EXIT
      export TERRANE_QUOTA_CONFINEMENT_VM=1
      ${image}/bin/quota-confinement-fixture owner /mnt/terrane-confinement/owner
    '';
  };
in {inherit image native;}
