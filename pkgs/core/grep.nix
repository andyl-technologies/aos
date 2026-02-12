# GNU Grep — Pattern matching utility
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "grep-${versions.core.grep}";
  version = versions.core.grep;

  src = fetchurl {
    inherit (sources.grep) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd grep-${versions.core.grep}
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
    description = "GNU Grep — search for patterns in files";
    homepage = "https://www.gnu.org/software/grep/";
    license = "GPL-3.0-or-later";
  };
}
