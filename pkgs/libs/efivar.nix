##! efivar — EFI variable and device-path libraries
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  gnumake,
  pkg-config,
  mandoc,
  popt,
}: let
  version = "39";
in
  mkDerivation {
    pname = "efivar";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/rhboot/efivar/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-ye3RXy7u6mMjLz5mmkjpkse+mv9X7iJnKsMfXsoWCaY=";
    };

    buildDeps = [gnumake pkg-config mandoc];
    runtimeDeps = [popt];
    propagatedDeps = [popt];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd efivar-${version}
        '';
      }
      {
        name = "build";
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # makeguids runs during the build. Keep its native compiler clear
            # of target include paths and link flags inherited from the stdenv.
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<'EOF'
            #!${buildPackages.bash}/bin/bash
            native_hardening=
            for flag in $AOS_HARDENING_ENABLE; do
              case "$flag" in
                pacret) ;;
                *) native_hardening="$native_hardening $flag" ;;
              esac
            done
            export AOS_HARDENING_ENABLE="$native_hardening"
            unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset NIX_CFLAGS_COMPILE NIX_LDFLAGS
            exec ${buildPackages.cc}/bin/cc "$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build
            export HOSTCC="$PWD/.aos-build-tools/cc-for-build"
            export HOSTCCLD="$HOSTCC"
            # Build generators must not depend on the builder's CPU features.
            sed -i 's/HOST_MARCH=-march=native/HOST_MARCH=/' src/include/defaults.mk
          ''
          + ''
            make -j"$NIX_BUILD_CORES" \
              PREFIX="$out" \
              LIBDIR="$out/lib" \
              BINDIR="$out/bin" \
              INCLUDEDIR="$out/include" \
              PCDIR="$out/lib/pkgconfig" \
              MANDOC="${mandoc}/bin/mandoc" \
              ENABLE_DOCS=1
          '';
      }
      {
        name = "install";
        script = ''
          make install \
            PREFIX="$out" \
            LIBDIR="$out/lib" \
            BINDIR="$out/bin" \
            INCLUDEDIR="$out/include" \
            PCDIR="$out/lib/pkgconfig" \
            MANDIR="$out/share/man" \
            MANDOC="${mandoc}/bin/mandoc" \
            ENABLE_DOCS=1
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-efivar";
        library = self;
        libs = ["-lefivar"];
        testSource = ''
          #include <efivar/efivar.h>

          int main(void) {
              efi_guid_t guid;
              return efi_str_to_guid("8be4df61-93ca-11d2-aa0d-00e098032b8c", &guid) < 0;
          }
        '';
      };
    };

    meta = {
      description = "EFI variable and device-path libraries";
      homepage = "https://github.com/rhboot/efivar";
      license = "LGPL-2.1-only";
    };
  }
