##! linux-pam — Pluggable Authentication Modules
{
  buildPackages,
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  flex,
  bison,
  gettext,
  python3,
  libxcrypt,
  audit,
  stdenv,
}: let
  version = "1.7.1";
in
  mkDerivation {
    pname = "linux-pam";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/linux-pam/linux-pam/releases/download/v${version}/Linux-PAM-${version}.tar.xz"
        "https://github.com/linux-pam/linux-pam/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-IdvOxuAd1XjxR4nqyQJKGJQebycCoFz5GyjCMu6yarA=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      flex
      bison
      gettext
      python3
    ];
    runtimeDeps = [
      libxcrypt
      audit
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd Linux-PAM-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Meson needs to find its own Python modules (ninja invokes
          # python3 -m mesonbuild.mesonmain directly).
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"

          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --buildtype=release \
            --libdir=lib \
            -Ddefault_library=both \
            -Ddocs=disabled \
            -Dexamples=false \
            -Dxtests=false \
            -Dnis=disabled \
            -Dselinux=disabled \
            -Delogind=disabled \
            -Dlogind=disabled \
            -Dopenssl=disabled \
            -Dpam_userdb=disabled \
            -Dpam_unix=enabled \
            -Daudit=enabled
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          ''
            ninja -C build install
          ''
          + lib.optionalString stdenv.isCross ''
            # Meson removes dependency RPATHs from cross-installed targets.
            # Restore only declared runtime directories for direct ELF edges;
            # consumers cannot supply these paths through transitive RUNPATHs.
            find "$out" -type f -print > runtime-objects

            repair_runtime_edge() {
              soname=$1
              runtime_directory=$2

              if [ ! -f "$runtime_directory/$soname" ]; then
                echo "linux-pam runtime library not found: $runtime_directory/$soname" >&2
                exit 1
              fi

              runtime_header=$(readelf -h "$runtime_directory/$soname")
              runtime_machine=$(printf '%s\n' "$runtime_header" |
                sed -n 's/.*Machine:[[:space:]]*//p')
              runtime_dynamic=$(readelf -d "$runtime_directory/$soname")
              if [ -z "$runtime_machine" ] \
                || ! printf '%s\n' "$runtime_dynamic" | \
                  grep -Fq "Library soname: [$soname]"; then
                echo "invalid linux-pam runtime library: $runtime_directory/$soname" >&2
                exit 1
              fi

              matched=false

              while IFS= read -r object; do
                dynamic=$(readelf -d "$object" 2>/dev/null) || continue
                if ! printf '%s\n' "$dynamic" | \
                  grep -Fq "Shared library: [$soname]"; then
                  continue
                fi

                object_machine=$(readelf -h "$object" |
                  sed -n 's/.*Machine:[[:space:]]*//p')
                if [ "$object_machine" != "$runtime_machine" ]; then
                  echo "linux-pam runtime architecture mismatch: $object -> $soname" >&2
                  exit 1
                fi

                matched=true
                rpath=$(${buildPackages.patchelf}/bin/patchelf --print-rpath "$object")
                case ":$rpath:" in
                  *":$runtime_directory:"*) ;;
                  *)
                    ${buildPackages.patchelf}/bin/patchelf \
                      --add-rpath "$runtime_directory" "$object"
                    ;;
                esac

                rpath=$(${buildPackages.patchelf}/bin/patchelf --print-rpath "$object")
                case ":$rpath:" in
                  *":$runtime_directory:"*) ;;
                  *)
                    echo "linux-pam runtime edge remains unresolved: $object -> $soname" >&2
                    exit 1
                    ;;
                esac
              done < runtime-objects

              if [ "$matched" != true ]; then
                echo "linux-pam expected direct runtime edge not found: $soname" >&2
                exit 1
              fi
            }

            repair_runtime_edge libaudit.so.1 ${audit}/lib
            repair_runtime_edge libcrypt.so.2 ${libxcrypt}/lib
            rm -f runtime-objects
          '';
      }
    ];

    meta = {
      description = "Pluggable Authentication Modules for Linux";
      homepage = "https://github.com/linux-pam/linux-pam";
      license = "BSD-3-Clause";
    };
  }
