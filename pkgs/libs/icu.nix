##! ICU4C — Unicode and globalization support library
{
  mkDerivation,
  fetchurl,
  gnumake,
  python3,
  buildPackages,
  stdenv,
}: let
  version = "77.1";
  sourceVersion = builtins.replaceStrings ["."] ["_"] version;
in
  mkDerivation {
    pname = "icu";
    inherit version;
    outputs = ["out" "cross"];

    src = fetchurl {
      urls = [
        "https://github.com/unicode-org/icu/releases/download/release-77-1/icu4c-${sourceVersion}-src.tgz"
      ];
      hash = "sha256-WI5DH3cyfDkDH/u4hDwOO8EiwhE3RIX6h9xfP6/yQGE=";
    };

    buildDeps = [
      gnumake
      python3
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.hostPlatform.isDarwin && stdenv.isCross
          then ''
            tar xf $src
            cd icu/source

            # Modern public Darwin SDKs no longer install tzfile.h. ICU
            # ships the matching IANA header for its tzcode tools.
            sed -i \
              's|#include <tzfile.h>|#include "../tools/tzcode/tzfile.h"|' \
              common/putil.cpp

            # The debug utility exposes these values through ICU's public
            # system-parameter API. Publish reusable target compiler names,
            # not this build's Linux-hosted cross-wrapper store paths.
            sed -i \
              's|"-DU_CC=\\"@CC@\\"" "-DU_CXX=\\"@CXX@\\""|"-DU_CC=\\"cc\\"" "-DU_CXX=\\"c++\\""|' \
              tools/toolutil/Makefile.in
          ''
          else if stdenv.hostPlatform.isDarwin
          then ''
            tar xf $src
            cd icu/source

            # Modern public Darwin SDKs no longer install tzfile.h. ICU
            # ships the matching IANA header for its tzcode tools.
            sed -i \
              's|#include <tzfile.h>|#include "../tools/tzcode/tzfile.h"|' \
              common/putil.cpp
          ''
          else ''
            tar xf $src
            cd icu/source
          '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # ICU otherwise records bare dylib basenames. Its rpath mode uses
            # the configured libdir as the install name, which keeps every
            # consumer resolvable directly from the immutable store output.
            ./configure \
              $configureFlags \
              ${
              if stdenv.isCross
              then "--with-cross-build=${buildPackages.icu.cross}/source"
              else ""
            } \
              --enable-rpath \
              --prefix=$out \
              --enable-shared \
              --enable-static
          ''
          else ''
            ./configure \
              $configureFlags \
              ${
              if stdenv.isCross
              then "--with-cross-build=${buildPackages.icu.cross}/source"
              else ""
            } \
              --prefix=$out \
              --enable-shared \
              --enable-static
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin && stdenv.isCross
          then ''
            make install

            # ICU publishes the compiler utilities used to build it for
            # downstream data packaging. Defer them to the consuming Darwin
            # stdenv instead of retaining this Linux-hosted cross wrapper and
            # its native compiler closure.
            metadata_dir="$out/lib/icu/${version}"
            sed -i \
              's|${stdenv.cc}/bin/||g' \
              "$metadata_dir/Makefile.inc" \
              "$metadata_dir/pkgdata.inc"
            if grep -F '${stdenv.cc}' \
              "$metadata_dir/Makefile.inc" \
              "$metadata_dir/pkgdata.inc"; then
              echo "ICU target metadata retains the cross compiler" >&2
              exit 1
            fi

            mkdir -p "$cross"
          ''
          else ''
            make install

            if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
              mkdir -p "$cross"
            else
              mkdir -p "$cross"
              cp -R . "$cross/source"
            fi
          '';
      }
    ];

    meta = {
      description = "ICU4C Unicode and globalization libraries";
      homepage = "https://icu.unicode.org/";
      license = "Unicode-3.0";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-icu";
        library = self;
        libs = ["-licuuc"];
        testSource = ''
          #include <unicode/uversion.h>
          int main(void) {
            UVersionInfo version;
            u_getVersion(version);
            return version[0] == 0;
          }
        '';
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libicuuc.so"];
      };
    };
  }
