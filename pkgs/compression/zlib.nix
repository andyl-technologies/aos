# zlib — Lossless data compression library
{ mkDerivation, fetchurl, make }:

let version = "1.3.1"; in
mkDerivation {
  pname = "zlib";
  inherit version;

  src = fetchurl {
    urls = [
      "https://zlib.net/zlib-${version}.tar.xz"
    ];
    hash = "sha256-OO+WuN/lENQnB9nHgYd5FHklQRM+GHCEFGO/pz+IPjI=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd zlib-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure --prefix=$out
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "zlib — lossless data compression library";
    homepage = "https://zlib.net";
    license = "Zlib";
  };
}
