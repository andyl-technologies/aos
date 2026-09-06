##! lzo — Low-latency lossless compression library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.10";
in
  mkDerivation {
    pname = "lzo";
    inherit version;

    src = fetchurl {
      urls = ["https://www.oberhumer.com/opensource/lzo/download/lzo-${version}.tar.gz"];
      hash = "sha256-wPiSlDIIJm+bZUOzrjCPq2KExckOYnkxRG+0m0IhoHI=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    configureFlags = "--enable-shared --enable-static";
    doCheck = true;

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-lzo";
        library = self;
        libs = ["-llzo2"];
        testSource = ''
          #include <lzo/lzo1x.h>
          int main(void) {
            return lzo_init() == LZO_E_OK ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Low-latency lossless data compression library";
      homepage = "https://www.oberhumer.com/opensource/lzo/";
      license = "GPL-2.0-or-later";
    };
  }
