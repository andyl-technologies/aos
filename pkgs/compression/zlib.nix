# zlib — Lossless data compression library
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "zlib-${versions.compression.zlib}";
  version = versions.compression.zlib;

  src = fetchurl {
    inherit (sources.zlib) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd zlib-${versions.compression.zlib}
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
