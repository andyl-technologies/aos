##! fuse3 — Low-level Filesystem in Userspace library
##!
##! Upstream does not split its low- and high-level APIs into separate shared
##! objects, so this package ships the complete dynamically linked libfuse3
##! library and public headers. AOS consumers use only the low-level custom-FD
##! session API; privileged mount operations and policy remain in the mount
##! broker. The DSO retains upstream mount-helper and mtab fallback strings,
##! but they are inert in that architecture: this output contains no helper,
##! utility, init script, udev rule, or mtab integration.
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
}: let
  version = "3.18.2";
in
  mkDerivation {
    pname = "fuse3";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libfuse/libfuse/releases/download/fuse-${version}/fuse-${version}.tar.gz"
      ];
      hash = "sha256-8B3oVxfiCt9fmK/zJKzYXdc9YaXKODTVc9zwvW5Uopg=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    # Build-system paths must not survive in the library, headers, or
    # pkg-config metadata and accidentally enlarge consumers' closures.
    outputChecks = {
      out = {
        disallowedReferences = [
          meson
          ninja
          pkg-config
        ];
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fuse-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --libdir=lib \
            --includedir=include \
            --buildtype=release \
            -Ddefault_library=shared \
            -Dutils=false \
            -Dexamples=false \
            -Dtests=false \
            -Duseroot=false \
            -Ddisable-mtab=true \
            -Denable-usdt=false \
            -Denable-io-uring=false \
            -Dinitscriptdir= \
            -Dudevrulesdir=
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${meson}/lib/python3/site-packages \
            ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${meson}/lib/python3/site-packages \
            ninja -C build install

          # Fail closed if a later upstream change makes any helper, policy
          # file, static archive, or other artifact part of this profile.
          actualManifest=$(
            find "$out" -type f -printf 'file %P\n'
            find "$out" -type l -printf 'symlink %P -> %l\n'
          )
          actualManifest=$(printf '%s\n' "$actualManifest" | sort)
          expectedManifest='file include/fuse3/cuse_lowlevel.h
          file include/fuse3/fuse.h
          file include/fuse3/fuse_common.h
          file include/fuse3/fuse_log.h
          file include/fuse3/fuse_lowlevel.h
          file include/fuse3/fuse_opt.h
          file include/fuse3/libfuse_config.h
          file lib/libfuse3.so.3.18.2
          file lib/pkgconfig/fuse3.pc
          symlink lib/libfuse3.so -> libfuse3.so.4
          symlink lib/libfuse3.so.4 -> libfuse3.so.3.18.2'

          if [ "$actualManifest" != "$expectedManifest" ]; then
            echo "unexpected fuse3 installation manifest:" >&2
            printf '%s\n' "$actualManifest" >&2
            exit 1
          fi
        '';
      }
    ];

    # The worker slice must add behavioral custom-FD handoff and Linux FUSE
    # UAPI parity gates. This package slice proves packaging and ABI metadata.
    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libfuse3.so"];
      };

      symbols = testing.mkSymbolCheck {
        pkg = self;
        libName = "libfuse3.so";
        symbols = [
          "fuse_passthrough_close"
          "fuse_passthrough_open"
          "fuse_session_custom_io_317"
          "fuse_session_receive_buf"
        ];
      };

      low-level-link = testing.mkLinkCheck {
        pname = "lib-fuse3-low-level";
        library = self;
        includes = ["${self}/include/fuse3"];
        libs = ["-lfuse3"];
        testSource = ''
          #define FUSE_USE_VERSION 317
          #include <fuse_lowlevel.h>

          #pragma GCC diagnostic error "-Wincompatible-pointer-types"

          int main(void) {
            int (*volatile custom_io)(struct fuse_session *,
                                      const struct fuse_custom_io *,
                                      size_t, int) = fuse_session_custom_io_317;
            int (*volatile passthrough_open)(fuse_req_t, int) =
              fuse_passthrough_open;
            int (*volatile passthrough_close)(fuse_req_t, int) =
              fuse_passthrough_close;

            return fuse_version() == 318 && custom_io != 0 &&
              passthrough_open != 0 && passthrough_close != 0 ? 0 : 1;
          }
        '';
      };

      abi-metadata = pkgs.mkDerivation {
        pname = "fuse3-abi-metadata-check";
        version = "0";
        src = null;

        buildDeps = [
          pkgs.elfutils
          pkgs.grep
        ];

        phases = [
          {
            name = "check";
            script = ''
              set -eu

              dynamic=dynamic.txt
              symbols=symbols.txt
              readelf --dynamic --wide ${self}/lib/libfuse3.so > "$dynamic"
              readelf --dyn-syms --wide ${self}/lib/libfuse3.so > "$symbols"

              sonameCount=$(grep -c '(SONAME)' "$dynamic")
              test "$sonameCount" -eq 1
              grep -F -q 'Library soname: [libfuse3.so.4]' "$dynamic"

              grep -F -q 'fuse_passthrough_open@@FUSE_3.17' "$symbols"
              grep -F -q 'fuse_passthrough_close@@FUSE_3.17' "$symbols"
              grep -F -q 'fuse_session_custom_io_317@@FUSE_3.17' "$symbols"

              mkdir -p "$out"
              printf '%s\n' 'soname=libfuse3.so.4' > "$out/result"
              printf '%s\n' 'custom-fd-symbol-version=FUSE_3.17' >> "$out/result"
            '';
          }
        ];
      };

      closure = pkgs.mkDerivation {
        pname = "fuse3-runtime-closure-check";
        version = "0";
        src = null;

        outputChecks = {};
        exportReferencesGraph.runtime = [self];
        buildDeps = [pkgs.jq];
        dontStrip = true;
        dontNukeRefs = true;

        phases = [
          {
            name = "check";
            script = ''
              set -eu

              size=$(jq '[.runtime[].narSize] | add // 0' "$NIX_ATTRS_JSON_FILE")
              maxBytes=$((32 * 1024 * 1024))
              if [ "$size" -gt "$maxBytes" ]; then
                echo "fuse3 runtime closure is $size bytes (max: $maxBytes)" >&2
                exit 1
              fi

              for buildTool in ${meson} ${ninja} ${pkg-config}; do
                if jq -e --arg path "$buildTool" '.runtime | any(.path == $path)' \
                  "$NIX_ATTRS_JSON_FILE" >/dev/null; then
                  echo "fuse3 runtime closure retains build tool: $buildTool" >&2
                  exit 1
                fi
              done

              if ! jq -e \
                --arg self ${self} \
                --arg glibc ${pkgs.glibc} \
                '([.runtime[].path] | sort) == ([$self, $glibc] | sort)' \
                "$NIX_ATTRS_JSON_FILE" >/dev/null; then
                echo "fuse3 runtime closure differs from the self+glibc allowlist:" >&2
                jq -r '.runtime[].path' "$NIX_ATTRS_JSON_FILE" >&2
                exit 1
              fi

              mkdir -p "$out"
              printf 'closure-bytes=%s\n' "$size" > "$out/result"
            '';
          }
        ];
      };
    };

    meta = {
      description = "Low-level Filesystem in Userspace library";
      homepage = "https://github.com/libfuse/libfuse";
      # The release LICENSE assigns include/, lib/, and meson.build to
      # version 2.1 of the LGPL. No GPL-only utility sources are installed.
      license = "LGPL-2.1-only";
    };
  }
