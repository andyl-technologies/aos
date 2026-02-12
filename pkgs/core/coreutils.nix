# GNU Coreutils — Basic file, shell, and text utilities
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "coreutils-${versions.core.coreutils}";
  version = versions.core.coreutils;

  src = fetchurl {
    inherit (sources.coreutils) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd coreutils-${versions.core.coreutils}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --without-gmp \
          --disable-nls \
          --enable-no-install-program=groups,hostname,kill,uptime
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
    description = "GNU Coreutils — basic file, shell, and text manipulation utilities";
    homepage = "https://www.gnu.org/software/coreutils/";
    license = "GPL-3.0-or-later";
  };
}
