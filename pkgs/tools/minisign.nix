# minisign — Dead simple signing tool
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "minisign-${versions.image-tools.minisign}";
  version = versions.image-tools.minisign;

  src = fetchurl {
    inherit (sources.minisign) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd minisign-${versions.image-tools.minisign}
      '';
    }
    { name = "build";
      script = ''
        mkdir -p build && cd build
        cmake .. \
          -DCMAKE_INSTALL_PREFIX=$out \
          -DCMAKE_BUILD_TYPE=Release
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        cd build
        make install
      '';
    }
  ];

  meta = {
    description = "minisign — simple tool to sign and verify files";
    homepage = "https://jedisct1.github.io/minisign/";
    license = "ISC";
  };
}
