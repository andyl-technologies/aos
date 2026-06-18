# lib/testing/package-root-image.nix - RFC-0001 dm-verity root image check.
{
  pkgs,
  lib,
}: let
  mkPackageRootImage = import ../build/package-root-image.nix {inherit pkgs lib;};

  referencedPackage = pkgs.grep;

  payload = pkgs.runCommand "package-root-image-payload" {REFERENCED_PACKAGE = referencedPackage;} ''
    mkdir -p "$out/nix"
    mkdir -p "$out/share/package-root-image"
    mkdir -p "$out/var/lib/package-root-image"
    printf payload > "$out/share/package-root-image/payload.txt"
    printf '%s\n' "$REFERENCED_PACKAGE" > "$out/share/package-root-image/reference.txt"
    printf state > "$out/var/lib/package-root-image/state.txt"
  '';

  imageArgs = {
    root = payload;
    minSizeMiB = 16;
    headroomMiB = 2;
    rootHashKey = "${pkgs.secure-boot-test-keys}/db.key";
    rootHashCert = "${pkgs.secure-boot-test-keys}/db.crt";
  };

  image = mkPackageRootImage (imageArgs // {pname = "package-root-image-check-root-a";});
  reproducibleImage = mkPackageRootImage (imageArgs // {pname = "package-root-image-check-root-b";});
in
  pkgs.mkDerivation {
    pname = "package-root-image-check";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.e2fsprogs
      pkgs.gawk
      pkgs.grep
      pkgs.openssl
    ];

    PAYLOAD = payload;
    REFERENCED_PACKAGE = referencedPackage;
    ROOT_IMAGE = image;
    REPRODUCIBLE_IMAGE = reproducibleImage;
    ROOT_HASH_CERT = "${pkgs.secure-boot-test-keys}/db.crt";

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          test -s "$ROOT_IMAGE/root.img"
          test -s "$ROOT_IMAGE/root.verity"
          test -s "$ROOT_IMAGE/root.roothash"
          test -s "$ROOT_IMAGE/root.roothash.p7s"
          test -s "$ROOT_IMAGE/image-manifest.json"
          test -s "$ROOT_IMAGE/store-paths"
          test -s "$REPRODUCIBLE_IMAGE/root.img"
          test -s "$REPRODUCIBLE_IMAGE/root.verity"
          test -s "$REPRODUCIBLE_IMAGE/root.roothash"
          test -s "$REPRODUCIBLE_IMAGE/root.roothash.p7s"

          cmp "$ROOT_IMAGE/root.img" "$REPRODUCIBLE_IMAGE/root.img"
          cmp "$ROOT_IMAGE/root.verity" "$REPRODUCIBLE_IMAGE/root.verity"
          cmp "$ROOT_IMAGE/root.roothash" "$REPRODUCIBLE_IMAGE/root.roothash"
          cmp "$ROOT_IMAGE/root.roothash.p7s" "$REPRODUCIBLE_IMAGE/root.roothash.p7s"

          root_hash=$(cat "$ROOT_IMAGE/root.roothash")
          printf '%s' "$root_hash" | grep -Eq '^[0-9a-f]{64}$'
          grep -q "\"root_hash\":\"sha256:$root_hash\"" "$ROOT_IMAGE/image-manifest.json"
          grep -q '"root_image":"root.img"' "$ROOT_IMAGE/image-manifest.json"
          grep -q '"root_verity":"root.verity"' "$ROOT_IMAGE/image-manifest.json"
          grep -q '"root_hash_sig":"root.roothash.p7s"' "$ROOT_IMAGE/image-manifest.json"

          grep -Fx "$PAYLOAD" "$ROOT_IMAGE/store-paths" >/dev/null
          payload_base=$(basename "$PAYLOAD")
          ${pkgs.e2fsprogs}/sbin/debugfs -R "stat /nix/store/$payload_base/share/package-root-image/payload.txt" \
            "$ROOT_IMAGE/root.img" > payload.stat
          grep -q 'Type: regular' payload.stat
          ${pkgs.e2fsprogs}/sbin/debugfs -R "stat /var/lib/package-root-image/state.txt" \
            "$ROOT_IMAGE/root.img" > state.stat
          grep -q 'Type: regular' state.stat

          grep -Fx "$REFERENCED_PACKAGE" "$ROOT_IMAGE/store-paths" >/dev/null
          referenced_base=$(basename "$REFERENCED_PACKAGE")
          ${pkgs.e2fsprogs}/sbin/debugfs -R "stat /nix/store/$referenced_base/bin/grep" \
            "$ROOT_IMAGE/root.img" > referenced.stat
          grep -q 'Type: regular' referenced.stat

          openssl cms -verify -binary \
            -inform DER \
            -in "$ROOT_IMAGE/root.roothash.p7s" \
            -content "$ROOT_IMAGE/root.roothash" \
            -CAfile "$ROOT_HASH_CERT" \
            -out /dev/null

          work=$TMPDIR/package-root-image
          mkdir -p "$work"
          cp "$ROOT_IMAGE/root.img" "$work/root.img"
          cp "$ROOT_IMAGE/root.verity" "$work/root.verity"
          chmod u+w "$work/root.img" "$work/root.verity"

          veritysetup verify "$work/root.img" "$work/root.verity" "$root_hash"

          cp "$work/root.img" "$work/tampered.img"
          chmod u+w "$work/tampered.img"
          printf X | dd of="$work/tampered.img" bs=1 seek=4096 conv=notrunc status=none
          if veritysetup verify "$work/tampered.img" "$work/root.verity" "$root_hash" >/dev/null 2>&1; then
            echo "dm-verity verification unexpectedly accepted a tampered package root" >&2
            exit 1
          fi

          mkdir -p "$out"
          {
            echo "root-image=$ROOT_IMAGE"
            echo "root-hash=$root_hash"
          } > "$out/result"
        '';
      }
    ];

    meta.description = "Build-check for hermetic signed dm-verity package roots";
  }
