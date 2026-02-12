# Zstandard — Fast real-time compression algorithm
{ mkDerivation, fetchurl, sources, versions, make, zlib }:

mkDerivation {
  name = "zstd-${versions.compression.zstd}";
  version = versions.compression.zstd;

  src = fetchurl {
    inherit (sources.zstd) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [ zlib ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd zstd-${versions.compression.zstd}
      '';
    }
    { name = "build";
      script = ''
        make PREFIX=$out -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install PREFIX=$out
      '';
    }
  ];

  meta = {
    description = "Zstandard — fast real-time compression algorithm";
    homepage = "https://facebook.github.io/zstd/";
    license = "BSD-3-Clause";
  };
}
