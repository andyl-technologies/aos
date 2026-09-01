##! tests/containers/phase0.nix — Executable RFC-0017 contract spikes.
##!
##! Freezes the first layer byte vector, proves the production golden package
##! roots are independently available, and exercises the daemonless Nix-store
##! initialization and baked-root retention contract used by the `aos` image.
{
  pkgs,
  lib,
  goldenRoots,
}: let
  expectedRootCount = builtins.length goldenRoots;
  goldenRootList = builtins.concatStringsSep "\n" (map builtins.toString goldenRoots);
  closureInfo = import ../../lib/build/closure-info.nix {inherit pkgs lib;} {
    rootPaths = goldenRoots;
    pname = "aos-container-phase0-closure-info";
  };
in
  assert builtins.elem pkgs.aos goldenRoots;
    pkgs.mkDerivation {
      pname = "aos-container-phase0-contract";
      version = "1";
      src = null;

      buildDeps = [
        pkgs.aos
        pkgs.coreutils
        pkgs.diffutils
        pkgs.findutils
        pkgs.gzip
        pkgs.jq
        pkgs.nix
        pkgs.tar
        closureInfo
      ];

      GOLDEN_ROOTS = goldenRootList;
      EXPECTED_ROOT_COUNT = toString expectedRootCount;

      dontStrip = true;
      dontNukeRefs = true;

      phases = [
        {
          name = "check";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $1" >&2
              exit 1
            }

            make_layer() {
              destination="$1"
              find fixture-root -mindepth 1 -printf '%P\0' \
                | sort -z > members
              tar \
                -C fixture-root \
                --null \
                --verbatim-files-from \
                --no-recursion \
                --format=gnu \
                --mtime=@1 \
                --clamp-mtime \
                --owner=0 \
                --group=0 \
                --numeric-owner \
                --no-acls \
                --no-selinux \
                --no-xattrs \
                --hard-dereference \
                -cf "$destination.tar" \
                --files-from="$PWD/members"
              gzip -n -9 -c "$destination.tar" > "$destination.tar.gz"
            }

            mkdir -p fixture-root/bin fixture-root/etc
            printf '%s\n' 'AOS OCI layer ABI v1' > fixture-root/etc/release
            printf '%s\n' '#!/fixed/interpreter' 'exit 0' > fixture-root/bin/tool
            chmod 0555 fixture-root/bin/tool
            chmod 0755 fixture-root/bin fixture-root/etc
            ln fixture-root/etc/release fixture-root/etc/release-hardlink
            ln -s ../etc/release fixture-root/bin/release-link

            make_layer layer-a
            touch -d @1000000000 fixture-root/bin fixture-root/etc \
              fixture-root/bin/tool fixture-root/etc/release
            make_layer layer-b

            cmp layer-a.tar layer-b.tar \
              || fail "normalized layer tar is not reproducible"
            cmp layer-a.tar.gz layer-b.tar.gz \
              || fail "normalized gzip layer is not reproducible"

            tar_sha=$(sha256sum layer-a.tar | cut -d ' ' -f 1)
            gzip_sha=$(sha256sum layer-a.tar.gz | cut -d ' ' -f 1)
            test "$tar_sha" = 6e30729d0413d5fb0dba4d0573093a4950e81cd45d7a9ebc2f62f09746b07ea5 \
              || fail "layer ABI DiffID vector changed: $tar_sha"
            test "$gzip_sha" = 1ec9791d8b0b3458830e5156881293d288941e793bb73790f85ad35f168a51d0 \
              || fail "layer ABI blob vector changed: $gzip_sha"

            printf '%s\n' "$GOLDEN_ROOTS" > golden-roots
            root_count=$(wc -l < golden-roots)
            test "$root_count" -eq "$EXPECTED_ROOT_COUNT" \
              || fail "golden root serialization lost entries"
            grep -Fx ${lib.escapeShellArg (builtins.toString pkgs.aos)} golden-roots >/dev/null \
              || fail "production golden roots do not contain pkgs.aos"

            isolated_root="$TMPDIR/isolated-root"
            store_uri="local?root=$isolated_root"
            nix_conf="$TMPDIR/nix-conf"
            mkdir -p \
              "$isolated_root/nix/store" \
              "$isolated_root/nix/var/nix/gcroots/aos-container-baked" \
              "$isolated_root/root" \
              "$nix_conf"
            printf '%s\n' \
              'experimental-features = nix-command' \
              'sandbox = false' \
              'build-users-group =' \
              'substituters =' > "$nix_conf/nix.conf"

            while IFS= read -r store_path; do
              cp -a --no-preserve=ownership \
                "$store_path" "$isolated_root/nix/store/"
            done < ${closureInfo}/store-paths

            NIX_CONF_DIR="$nix_conf" nix-store --store "$store_uri" --init
            NIX_CONF_DIR="$nix_conf" nix-store --store "$store_uri" \
              --load-db < ${closureInfo}/registration

            while IFS= read -r root; do
              root_name=''${root##*/}
              ln -s "$root" \
                "$isolated_root/nix/var/nix/gcroots/aos-container-baked/$root_name"
            done < golden-roots

            NIX_CONF_DIR="$nix_conf" nix-store --store "$store_uri" --gc
            while IFS= read -r root; do
              NIX_CONF_DIR="$nix_conf" nix-store --store "$store_uri" \
                --check-validity "$root" \
                || fail "baked root was collected: $root"
              test -e "$isolated_root$root" \
                || fail "baked root bytes were collected: $root"
            done < golden-roots

            export HOME="$isolated_root/root"
            export NIX_CONF_DIR="$nix_conf"
            export NIX_REMOTE="$store_uri"
            ${pkgs.aos}/bin/aos --version >/dev/null
            ${pkgs.aos}/bin/apm --help >/dev/null
            ${pkgs.aos}/bin/apr --help >/dev/null

            mkdir -p "$out"
            jq -S -n \
              --arg schema "aos.container.phase0-evidence/v1" \
              --arg tarSha256 "$tar_sha" \
              --arg gzipSha256 "$gzip_sha" \
              --argjson goldenRootCount "$root_count" \
              --argjson closurePathCount "$(wc -l < ${closureInfo}/store-paths)" \
              '{
                schema: $schema,
                layerAbi: {
                  tarSha256: $tarSha256,
                  gzipSha256: $gzipSha256
                },
                goldenRootCount: $goldenRootCount,
                closurePathCount: $closurePathCount,
                daemonlessCommands: ["aos --version", "apm --help", "apr --help"],
                bakedRootsSurviveGc: true
              }' > "$out/evidence.json"
          '';
        }
      ];

      meta.description = "Executable Phase-0 contracts for AOS OCI containers";
    }
