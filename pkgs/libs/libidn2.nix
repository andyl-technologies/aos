##! libidn2 — IDNA2008 and Unicode TR46 implementation
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gettext,
  libunistring,
}: let
  version = "2.3.8";
in
  mkDerivation {
    pname = "libidn2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/libidn/libidn2-${version}.tar.gz"
      ];
      hash = "sha256-9VeRG/YXFiHh9y/zX1sYJbs1tS7UUyXc3ukx5dPAeHo=";
    };

    buildDeps = [gnumake pkg-config gettext];
    runtimeDeps = [libunistring];
    propagatedDeps = [libunistring];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libidn2-${version}
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
        pname = "lib-libidn2";
        library = self;
        libs = ["-lidn2"];
        testSource = ''
          #include <idn2.h>
          #include <stdio.h>

          int main(void) {
              char *ascii = NULL;
              int result = idn2_lookup_u8(
                  (const uint8_t *)"example.com",
                  (uint8_t **)&ascii,
                  0);
              if (result != IDN2_OK) return 1;
              printf("%s\n", ascii);
              idn2_free(ascii);
              return 0;
          }
        '';
      };

      tool = testing.mkToolCheck {
        pname = "tool-idn2";
        tool = self;
        command = "idn2 --version";
      };
    };

    meta = {
      description = "IDNA2008 and Unicode TR46 implementation";
      homepage = "https://www.gnu.org/software/libidn/#libidn2";
      license = "LGPL-3.0-or-later AND GPL-2.0-or-later AND GPL-3.0-or-later";
      mainProgram = "idn2";
    };
  }
