# GNU Texinfo — Documentation system
{ mkDerivation, fetchurl, sources, versions, make, perl }:

mkDerivation {
  name = "texinfo-${versions.core.texinfo}";
  version = versions.core.texinfo;

  src = fetchurl {
    inherit (sources.texinfo) url hash;
  };

  buildDeps = [ make perl ];
  runtimeDeps = [ perl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd texinfo-${versions.core.texinfo}
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
    description = "GNU Texinfo — documentation system for online and printed output";
    homepage = "https://www.gnu.org/software/texinfo/";
    license = "GPL-3.0-or-later";
  };
}
