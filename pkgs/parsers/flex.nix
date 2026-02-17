##! flex — Fast lexical analyzer generator
{
  mkDerivation,
  fetchurl,
  make,
  m4,
}: let
  version = "2.6.4";
in
  mkDerivation {
    pname = "flex";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/westes/flex/releases/download/v${version}/flex-${version}.tar.gz"
      ];
      hash = "sha256-6HquAyvwfCb4WsDtMlCZjDdiHZX4vXSLMfFbM8Re6ZU=";
    };

    buildDeps = [
      make
      m4
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd flex-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out
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
      description = "flex — fast lexical analyzer generator";
      homepage = "https://github.com/westes/flex";
      license = "BSD-2-Clause";
    };
  }
