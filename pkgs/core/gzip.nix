# GNU Gzip — Compression utility
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "gzip-${versions.core.gzip}";
  version = versions.core.gzip;

  src = fetchurl {
    inherit (sources.gzip) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd gzip-${versions.core.gzip}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out
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
    description = "GNU Gzip — data compression program";
    homepage = "https://www.gnu.org/software/gzip/";
    license = "GPL-3.0-or-later";
  };
}
