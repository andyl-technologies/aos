##! libpng — PNG reference library
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}: let
  version = "1.6.58";
in
  mkDerivation {
    pname = "libpng";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.sourceforge.net/libpng/libpng-${version}.tar.xz"
      ];
      hash = "sha256-KOtAP1Hw90BSSRMs7P6C6lwO+X8bMsWmWCiBSuDTR3U=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [zlib];
    propagatedDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libpng-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          make check
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libpng";
        library = self;
        libs = ["-lpng"];
        testSource = ''
          #include <png.h>

          int main(void) {
              return png_access_version_number() == 0;
          }
        '';
      };
    };

    meta = {
      description = "Reference library for reading and writing PNG images";
      homepage = "http://www.libpng.org/pub/png/libpng.html";
      license = "libpng-2.0";
    };
  }
