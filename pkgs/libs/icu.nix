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
        script = ''
          tar xf $src
          cd icu/source
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            ${
            if stdenv.isCross
            then "--with-cross-build=${buildPackages.icu.cross}"
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
        script = ''
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
