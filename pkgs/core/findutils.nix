# GNU Findutils — find, xargs, and locate
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "findutils-${versions.core.findutils}";
  version = versions.core.findutils;

  src = fetchurl {
    inherit (sources.findutils) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd findutils-${versions.core.findutils}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls
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
    description = "GNU Findutils — find, xargs, and locate utilities";
    homepage = "https://www.gnu.org/software/findutils/";
    license = "GPL-3.0-or-later";
  };
}
