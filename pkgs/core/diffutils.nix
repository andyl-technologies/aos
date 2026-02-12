# GNU Diffutils — File comparison utilities
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "diffutils-${versions.core.diffutils}";
  version = versions.core.diffutils;

  src = fetchurl {
    inherit (sources.diffutils) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd diffutils-${versions.core.diffutils}
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
    description = "GNU Diffutils — file comparison utilities (diff, cmp, sdiff, diff3)";
    homepage = "https://www.gnu.org/software/diffutils/";
    license = "GPL-3.0-or-later";
  };
}
