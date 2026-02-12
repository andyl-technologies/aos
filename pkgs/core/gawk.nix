# GNU Awk — Pattern scanning and processing language
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "gawk-${versions.core.gawk}";
  version = versions.core.gawk;

  src = fetchurl {
    inherit (sources.gawk) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd gawk-${versions.core.gawk}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls \
          --without-readline
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
    description = "GNU Awk — pattern scanning and processing language";
    homepage = "https://www.gnu.org/software/gawk/";
    license = "GPL-3.0-or-later";
  };
}
