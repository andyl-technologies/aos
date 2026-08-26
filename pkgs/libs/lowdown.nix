##! lowdown — Simple Markdown translator
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "1.2.0";
in
  mkDerivation {
    pname = "lowdown";
    inherit version;

    src = fetchurl {
      urls = [
        "https://kristaps.bsd.lv/lowdown/snapshots/lowdown-${version}.tar.gz"
      ];
      hash = "sha256-SoU+Hkm8pu9TLQdSKLhFhaKdiLv0p9JqcMXU3yYLmj8=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            tar xf $src
            cd lowdown-${version}

            # These headers only supplied types and declarations which the
            # bundled base64 fallback does not use.
            sed -i '/#include <arpa\/nameser\.h>/d; /#include <resolv\.h>/d' compats.c
          ''
          else ''
            tar xf $src
            cd lowdown-${version}
          '';
      }
      {
        name = "configure";
        script = ''
          ./configure PREFIX=$out
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              sed -i 's/liblowdown\.so/liblowdown.dylib/g' Makefile
              sed -i 's|-Wl,[^ ]* |-Wl,-install_name,@rpath/$@.$(LIBVER) |' Makefile
            ''
            else ""
          }
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
          make install install_shared
        '';
      }
    ];

    meta = {
      description = "lowdown — simple Markdown translator";
      homepage = "https://kristaps.bsd.lv/lowdown/";
      license = "ISC";
    };
  }
