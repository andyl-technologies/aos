##! Oniguruma — regular expression library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "6.9.10";
in
  mkDerivation {
    pname = "oniguruma";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/kkos/oniguruma/releases/download/v${version}/onig-${version}.tar.gz"
      ];
      hash = "sha256-Klz8WuJZ5Ol/hraN//wVLNr/6U4gYLdwy4JyONdp/AU=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd onig-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --enable-posix-api=yes
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
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-oniguruma";
        library = self;
        libs = ["-lonig"];
        testSource = ''
          #include <oniguruma.h>
          #include <stdio.h>
          int main() {
            printf("oniguruma version: %s\n", onig_version());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "Oniguruma — regular expression library";
      homepage = "https://github.com/kkos/oniguruma";
      license = "BSD-2-Clause";
    };
  }
