# GNU Sed — Stream editor
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "sed-${versions.core.sed}";
  version = versions.core.sed;

  src = fetchurl {
    inherit (sources.sed) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd sed-${versions.core.sed}
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
    description = "GNU Sed — stream editor for filtering and transforming text";
    homepage = "https://www.gnu.org/software/sed/";
    license = "GPL-3.0-or-later";
  };
}
