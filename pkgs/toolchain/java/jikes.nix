##! jikes — Jikes Java compiler (C++ implementation, outputs Java 1.4 bytecode)
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "1.22";
in
mkDerivation {
  pname = "jikes";
  inherit version;

  src = fetchurl {
    urls = [
      "https://downloads.sourceforge.net/project/jikes/Jikes/${version}/jikes-${version}.tar.bz2"
    ];
    hash = "sha256-DLAsdjvEQTSfbTjKzVKt92IwLM46COJp8fdfcm5uFOM=";
  };

  buildDeps = [gnumake];
  runtimeDeps = [];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd jikes-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        CXXFLAGS="-fpermissive" ./configure --prefix=$out
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
    description = "Jikes — fast Java compiler written in C++";
    homepage = "https://jikes.sourceforge.net/";
    license = "IPL-1.0";
  };
}
