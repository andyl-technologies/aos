##! lowdown — Simple Markdown translator
{
  mkDerivation,
  fetchurl,
  make,
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

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd lowdown-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure PREFIX=$out
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
