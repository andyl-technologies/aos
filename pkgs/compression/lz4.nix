# LZ4 — Extremely fast compression algorithm
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.9.4";
in
mkDerivation {
  pname = "lz4";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/lz4/lz4/releases/download/v${version}/lz4-${version}.tar.gz"
    ];
    hash = "sha256-Cw46oHyMBj3fQLCCvffjehVivaQKD/UnKVfz6Yfg5Us=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd lz4-${version}
      '';
    }
    {
      name = "build";
      script = ''
        make PREFIX=$out -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
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
