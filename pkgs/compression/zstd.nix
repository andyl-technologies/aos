# Zstandard — Fast real-time compression algorithm
{
  mkDerivation,
  fetchurl,
  make,
  zlib,
}:

let
  version = "1.5.6";
in
mkDerivation {
  pname = "zstd";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/facebook/zstd/releases/download/v${version}/zstd-${version}.tar.gz"
    ];
    hash = "sha256-jCngbPQqrMHq/EB3ri7Gxvy5amJhV+BZPV6Co0/UA8E=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ zlib ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd zstd-${version}
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
    description = "Zstandard — fast real-time compression algorithm";
    homepage = "https://facebook.github.io/zstd/";
    license = "BSD-3-Clause";
  };
}
