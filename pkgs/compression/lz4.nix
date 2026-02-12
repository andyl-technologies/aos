# LZ4 — Extremely fast compression algorithm
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "lz4-${versions.compression.lz4}";
  version = versions.compression.lz4;

  src = fetchurl {
    inherit (sources.lz4) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd lz4-${versions.compression.lz4}
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
    description = "LZ4 — extremely fast compression algorithm";
    homepage = "https://lz4.org";
    license = "BSD-2-Clause";
  };
}
