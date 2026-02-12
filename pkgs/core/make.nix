# GNU Make — Build automation tool
{ mkDerivation, fetchurl, sources, versions }:

mkDerivation {
  name = "make-${versions.core.make}";
  version = versions.core.make;

  src = fetchurl {
    inherit (sources.make) url hash;
  };

  buildDeps = [];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd make-${versions.core.make}
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
    description = "GNU Make — a tool to control the generation of executables";
    homepage = "https://www.gnu.org/software/make/";
    license = "GPL-3.0-or-later";
  };
}
