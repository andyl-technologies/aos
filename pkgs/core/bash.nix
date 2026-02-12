# GNU Bash — Bourne-Again SHell
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "bash-${versions.core.bash}";
  version = versions.core.bash;

  src = fetchurl {
    inherit (sources.bash) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd bash-${versions.core.bash}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --without-bash-malloc \
          --with-installed-readline \
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
        ln -sf bash $out/bin/sh
      '';
    }
  ];

  meta = {
    description = "GNU Bash — the Bourne-Again SHell";
    homepage = "https://www.gnu.org/software/bash/";
    license = "GPL-3.0-or-later";
  };
}
