# pkg-config — Helper tool for compiling applications and libraries
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "pkg-config-${versions.core.pkg-config}";
  version = versions.core.pkg-config;

  src = fetchurl {
    inherit (sources.pkg-config) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd pkg-config-${versions.core.pkg-config}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-internal-glib \
          --disable-host-tool
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
    description = "pkg-config — helper tool for compiling applications and libraries";
    homepage = "https://www.freedesktop.org/wiki/Software/pkg-config/";
    license = "GPL-2.0-or-later";
  };
}
