##! libunistring — Unicode string processing library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
}: let
  version = "1.4.2";
in
  mkDerivation {
    pname = "libunistring";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/libunistring/libunistring-${version}.tar.gz"
      ];
      hash = "sha256-6CZksXAGTmIzGWISayWdRS1Tsie7SpOrIAQNhG/sAdg=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libunistring-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libunistring";
        library = self;
        libs = ["-lunistring"];
        testSource = ''
          #include <unistr.h>
          #include <stdio.h>

          int main(void) {
              const uint8_t input[] = "AOS";
              printf("%zu\n", u8_strlen(input));
              return u8_strlen(input) == 3 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Unicode string processing library";
      homepage = "https://www.gnu.org/software/libunistring/";
      license = "LGPL-3.0-or-later";
    };
  }
