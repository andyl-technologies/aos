##! Expat — XML parsing library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.7.4";
in
  mkDerivation {
    pname = "expat";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libexpat/libexpat/releases/download/R_${
          builtins.replaceStrings ["."] ["_"] version
        }/expat-${version}.tar.xz"
      ];
      hash = "sha256-npyrtFfB4J3pHbJwbYNlZFeSY46zvh+U27IUkwEIasA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd expat-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --enable-shared \
            --without-docbook
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
        pname = "lib-expat";
        library = self;
        libs = ["-lexpat"];
        testSource = ''
          #include <expat.h>
          #include <stdio.h>
          int main() {
            printf("expat version: %s\n", XML_ExpatVersion());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "Expat — XML parsing C library";
      homepage = "https://libexpat.github.io/";
      license = "MIT";
    };
  }
