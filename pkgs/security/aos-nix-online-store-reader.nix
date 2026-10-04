##! Fixed-domain readback through the selected Nix Store and HashSink engines.
##!
##! This two-stage factory accepts public domain DATA, never credentials or a
##! runtime root. The post-finalization header pins final installed bytes; it
##! grants no currentness, floor, snapshot or execution authority.
{
  mkDerivation,
  nix,
  nlohmann-json,
  boost,
  pkg-config,
  coreutils,
  gcc-libs,
  stdenv,
  buildPackages,
}: {
  domainIdHex,
}: let
  validDomain =
    builtins.isString domainIdHex
    && builtins.match "[0-9a-f]{32}" domainIdHex != null
    && domainIdHex != "00000000000000000000000000000000";
  domainRoot = "/var/lib/aos/sandbox-nix/domains/${domainIdHex}/root";
  buildPkgConfig = if stdenv.isCross then buildPackages.pkg-config else pkg-config;
  buildCoreutils = if stdenv.isCross then buildPackages.coreutils else coreutils;
in
  assert validDomain;
  assert nix.version == "2.24.12";
    mkDerivation {
      pname = "aos-nix-online-store-reader-${domainIdHex}";
      version = "1";
      src = ./aos-nix-online-store-reader;
      buildDeps = [nix.dev nlohmann-json boost.dev buildPkgConfig buildCoreutils];
      runtimeDeps = [nix gcc-libs];
      propagatedDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "build";
          script = ''
            # Nix.dev holds the headers; its library paths refer to Nix.out.
            # The release's installed configuration headers are required by
            # the same public C++ headers used by the upstream library build.
            $CXX -std=c++20 -O2 -Wall -Wextra \
              -I${nix.dev}/include/nix \
              -include config-util.hh -include config-store.hh -include config-main.hh \
              -DAOS_NIX_ONLINE_DOMAIN_ROOT='${builtins.toJSON domainRoot}' \
              reader.cc $(pkg-config --cflags --libs nix-store nix-main nix-util) \
              -Wl,-rpath,${nix}/lib -o aos-nix-online-store-reader
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/libexec"
            cp aos-nix-online-store-reader "$out/libexec/"
            chmod 0555 "$out/libexec/aos-nix-online-store-reader"
          '';
        }
      ];

      # Digests must follow strip, reference scrubbing and target metadata.
      # The header is a dependency of sandboxd, never an input to this reader.
      postFinalize = ''
        program="$out/libexec/aos-nix-online-store-reader"
        loader=$(cat ${stdenv.cc}/nix-support/dynamic-linker)
        loader=$(readlink -f "$loader")
        test -x "$program"
        test -f "$loader"

        emit_digest() {
          constant_name=$1
          image_path=$2
          digest_record=$(sha256sum "$image_path")
          digest_hex=''${digest_record%% *}
          test "''${#digest_hex}" -eq 64

          printf 'pub(super) const %s: [u8; 32] = [' "$constant_name"
          digest_position=1
          while test "$digest_position" -le 63; do
            digest_end=$((digest_position + 1))
            digest_byte=$(printf '%s' "$digest_hex" | cut -c "$digest_position-$digest_end")
            printf '0x%s,' "$digest_byte"
            digest_position=$((digest_position + 2))
          done
          printf '];\n'
        }

        header="$out/selected-reader.rs"
        {
          printf '%s\n' 'pub(super) const DOMAIN_ID_HEX: &str = ${builtins.toJSON domainIdHex};'
          printf '%s\n' 'pub(super) const DOMAIN_ROOT: &str = ${builtins.toJSON domainRoot};'
          printf 'pub(super) const READER_PATH: &str = "%s";\n' "$program"
          printf 'pub(super) const LOADER_PATH: &str = "%s";\n' "$loader"
          emit_digest READER_CONTENT_SHA256 "$program"
          emit_digest LOADER_CONTENT_SHA256 "$loader"
        } > "$header"
        chmod 0444 "$header"
      '';

      passthru = {
        inherit domainIdHex domainRoot;
        readerRelativePath = "libexec/aos-nix-online-store-reader";
        selectionHeaderRelativePath = "selected-reader.rs";
      };

      meta = {
        description = "Fixed-domain Nix2.24.12 read-only store hash-and-size reader";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }
