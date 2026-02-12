# GNU Bison — Parser generator
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "bison-${versions.core.bison}";
  version = versions.core.bison;

  src = fetchurl {
    inherit (sources.bison) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd bison-${versions.core.bison}
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
    description = "GNU Bison — general-purpose parser generator";
    homepage = "https://www.gnu.org/software/bison/";
    license = "GPL-3.0-or-later";
  };
}
