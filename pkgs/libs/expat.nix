##! Expat — XML parsing library
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "2.6.4";
in
mkDerivation {
  pname = "expat";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/libexpat/libexpat/releases/download/R_${
        builtins.replaceStrings [ "." ] [ "_" ] version
      }/expat-${version}.tar.xz"
    ];
    hash = "sha256-ppVina4EcFWzfVCg/0d20dRdCkyELPTM7hWEQfVf9+4=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

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

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      link = testing.mkLinkCheck {
        pname = "lib-expat";
        library = self;
        libs = [ "-lexpat" ];
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
