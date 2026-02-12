# GNU Tar — Archiving utility
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "tar-${versions.core.tar}";
  version = versions.core.tar;

  src = fetchurl {
    inherit (sources.tar) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd tar-${versions.core.tar}
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
    description = "GNU Tar — archiving utility";
    homepage = "https://www.gnu.org/software/tar/";
    license = "GPL-3.0-or-later";
  };
}
