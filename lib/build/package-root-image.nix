##! lib/build/package-root-image.nix - dm-verity package-root image builder.
##!
##! Builds a read-only ext4 image from a package root directory plus its store
##! closure, formats a separate dm-verity hash tree with AOS-built cryptsetup,
##! and emits a PKCS#7 signature over the root hash. The builder deliberately
##! uses `mkfs.ext4 -d` under fakeroot, matching lib/build/rootfs.nix, so it
##! stays sandbox-compatible and never mounts loop devices.
{
  pkgs,
  lib,
}: {
  root,
  pname ? "aos-package-root-image",
  label ? "aos-pkg-root",
  minSizeMiB ? 32,
  headroomMiB ? 4,
  fsUuid ? null,
  verityUuid ? null,
  veritySalt ? null,
  rootHashKey,
  rootHashCert,
}: let
  rootPath = builtins.toString root;
  mkUuid = seed: let
    hash = builtins.hashString "sha256" seed;
  in "${builtins.substring 0 8 hash}-${builtins.substring 8 4 hash}-4${builtins.substring 13 3 hash}-8${builtins.substring 17 3 hash}-${builtins.substring 20 12 hash}";
  actualFsUuid =
    if fsUuid == null
    then mkUuid "aos-package-root-image:fs:${rootPath}:${label}"
    else fsUuid;
  actualVerityUuid =
    if verityUuid == null
    then mkUuid "aos-package-root-image:verity:${rootPath}:${label}"
    else verityUuid;
  actualVeritySalt =
    if veritySalt == null
    then builtins.substring 0 64 (builtins.hashString "sha256" "aos-package-root-image:salt:${rootPath}:${label}")
    else veritySalt;
in
  pkgs.mkDerivation {
    inherit pname;
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.e2fsprogs
      pkgs.fakeroot
      pkgs.findutils
      pkgs.gawk
      pkgs.grep
      pkgs.openssl
      pkgs.cryptsetup
    ];

    ROOT = rootPath;
    FS_UUID = actualFsUuid;
    ROOT_HASH_KEY = builtins.toString rootHashKey;
    ROOT_HASH_CERT = builtins.toString rootHashCert;
    VERITY_UUID = actualVerityUuid;
    VERITY_SALT = actualVeritySalt;
    exportReferencesGraph = ["closure" root];

    phases = [
      {
        name = "populate";
        script = ''
          set -eu

          grep -h '^/nix/store/' closure | sort -u > store-paths

          test -d "$ROOT"
          mkdir -p rootfs
          cp -a "$ROOT"/. rootfs/

          for d in rootfs rootfs/nix rootfs/nix/store rootfs/tmp rootfs/var rootfs/var/tmp \
                   rootfs/run rootfs/dev rootfs/proc rootfs/sys rootfs/var/lib; do
            if [ -d "$d" ]; then
              chmod u+w "$d"
            fi
          done

          # RootImage= services still bind-mount host-provided paths such as
          # /nix/store and overlay tmp/state directories. Precreate common
          # mountpoints so systemd does not depend on payload-owned directories.
          mkdir -p rootfs/nix/store rootfs/tmp rootfs/var/tmp rootfs/run
          mkdir -p rootfs/run/aos-secure-boot-efivars
          mkdir -p rootfs/dev rootfs/proc rootfs/sys rootfs/var/lib
          chmod 1777 rootfs/tmp rootfs/var/tmp

          total=$(wc -l < store-paths)
          count=0
          while IFS= read -r p; do
            count=$((count + 1))
            if [ $((count % 50)) -eq 0 ] || [ "$count" -eq "$total" ]; then
              printf '\r    [%d/%d]' "$count" "$total"
            fi
            if [ ! -e "$p" ]; then
              echo ""
              echo "missing closure store path: $p" >&2
              exit 1
            fi
            cp -a "$p" rootfs/nix/store/
          done < store-paths
          echo ""

          find rootfs -exec touch -h -d @1 {} +
        '';
      }
      {
        name = "mkfs";
        script = ''
          set -eu
          export SOURCE_DATE_EPOCH=1
          export E2FSPROGS_FAKE_TIME=1

          apparent_kb=$(du -sk --apparent-size rootfs | cut -f1)
          apparent_mib=$(( apparent_kb / 1024 ))
          initial_mib=$(( apparent_mib * 3 / 2 + ${toString headroomMiB} + 8 ))
          if [ "$initial_mib" -lt ${toString minSizeMiB} ]; then
            initial_mib=${toString minSizeMiB}
          fi

          fakeroot -- mkfs.ext4 -d rootfs -L ${lib.escapeShellArg label} -m 0 -q \
            -b 4096 \
            -U "$FS_UUID" \
            -E "hash_seed=$FS_UUID,lazy_itable_init=0,lazy_journal_init=0" \
            root.img "''${initial_mib}M"

          e2fsck -f -y root.img >/dev/null
          resize2fs -M root.img >/dev/null 2>&1
          blk_size=$(dumpe2fs -h root.img 2>/dev/null \
                     | gawk '/Block size:/{print $3}')
          min_blocks=$(dumpe2fs -h root.img 2>/dev/null \
                       | gawk '/Block count:/{print $3}')
          headroom_blocks=$(( ${toString headroomMiB} * 1048576 / blk_size ))
          final_blocks=$(( min_blocks + headroom_blocks ))
          resize2fs root.img "$final_blocks" >/dev/null 2>&1
          final_bytes=$(( final_blocks * blk_size ))
          final_bytes=$(( ((final_bytes + 1048575) / 1048576) * 1048576 ))
          truncate -s "$final_bytes" root.img

          # resize2fs rewrites s_lastcheck from the wall clock even with
          # E2FSPROGS_FAKE_TIME set; normalize it before hashing/signing.
          debugfs -w -R "set_super_value lastcheck 1" root.img >/dev/null 2>&1
          echo "$final_bytes" > rootfs-size-bytes
        '';
      }
      {
        name = "verity";
        script = ''
          set -eu

          veritysetup format --salt "$VERITY_SALT" --uuid "$VERITY_UUID" \
            root.img root.verity > veritysetup.out
          root_hash=$(
            gawk -F: '/Root hash:/ {
              gsub(/^[ \t]+/, "", $2);
              print $2
            }' veritysetup.out
          )
          if ! printf '%s' "$root_hash" | grep -Eq '^[0-9a-f]{64}$'; then
            echo "invalid dm-verity root hash: $root_hash" >&2
            exit 1
          fi

          # Linux verifies the PKCS#7 over the ASCII hex root hash string, not
          # decoded hash bytes; dm-verity passes argv[8] to verify_pkcs7_signature.
          printf '%s' "$root_hash" > root.roothash
          openssl cms -sign -binary \
            -in root.roothash \
            -signer "$ROOT_HASH_CERT" \
            -inkey "$ROOT_HASH_KEY" \
            -outform DER \
            -out root.roothash.p7s \
            -nosmimecap \
            -noattr

          openssl cms -verify -binary \
            -inform DER \
            -in root.roothash.p7s \
            -content root.roothash \
            -CAfile "$ROOT_HASH_CERT" \
            -out /dev/null

          veritysetup verify root.img root.verity "$root_hash"
          stat -c %s root.verity > root-verity-size-bytes
        '';
      }
      {
        name = "install";
        script = ''
          set -eu

          mkdir -p "$out"
          mv root.img "$out/root.img"
          mv root.verity "$out/root.verity"
          mv root.roothash "$out/root.roothash"
          mv root.roothash.p7s "$out/root.roothash.p7s"
          mv rootfs-size-bytes "$out/rootfs-size-bytes"
          mv root-verity-size-bytes "$out/root-verity-size-bytes"
          mv store-paths "$out/store-paths"
          mv veritysetup.out "$out/veritysetup.out"

          root_hash=$(cat "$out/root.roothash")
          cat > "$out/image-manifest.json" <<EOF
          {"format":"ext4-verity","root_image":"root.img","root_verity":"root.verity","root_hash":"sha256:$root_hash","root_hash_sig":"root.roothash.p7s"}
          EOF
        '';
      }
    ];

    passthru = {
      inherit rootPath;
      imageFormat = "ext4-verity";
      imageManifest = "image-manifest.json";
      fsUuid = actualFsUuid;
      imageMembers = {
        root_image = "root.img";
        root_verity = "root.verity";
        root_hash_file = "root.roothash";
        root_hash_sig = "root.roothash.p7s";
      };
      veritySalt = actualVeritySalt;
      verityUuid = actualVerityUuid;
    };

    meta = {
      description = "Build a signed dm-verity ext4 image for an AOS package root";
    };
  }
