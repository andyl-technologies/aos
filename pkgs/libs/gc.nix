##! gc — Boehm-Demers-Weiser conservative garbage collector
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "8.2.12";
in
  mkDerivation {
    pname = "gc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ivmai/bdwgc/releases/download/v${version}/gc-${version}.tar.gz"
      ];
      hash = "sha256-QuUZStBqtv+4Bsg+uZwDRitJXZec2ngvPHLAivgzzU4=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gc-${version}
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
            --enable-cplusplus \
            --enable-large-config \
            --enable-threads=posix
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

    meta = {
      description = "gc — Boehm-Demers-Weiser conservative garbage collector";
      homepage = "https://www.hboehm.info/gc/";
      license = "MIT";
    };
  }
