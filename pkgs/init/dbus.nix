# D-Bus — Message bus system
{ mkDerivation, fetchurl, sources, versions, make, pkg-config }:

mkDerivation {
  name = "dbus-${versions.init.dbus}";
  version = versions.init.dbus;

  src = fetchurl {
    inherit (sources.dbus) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd dbus-${versions.init.dbus}
      '';
    }
    { name = "configure";
      script = ''
        mkdir -p build && cd build
        meson setup .. \
          --prefix=$out \
          --buildtype=release \
          -Dmodular_tests=disabled \
          -Ddoxygen_docs=disabled \
          -Dxml_docs=disabled \
          -Dsystemd=disabled \
          -Duser_session=false \
          -Dapparmor=disabled \
          -Dselinux=disabled \
          -Dlibaudit=disabled
      '';
    }
    { name = "build";
      script = ''
        cd build
        ninja -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        cd build
        ninja install
      '';
    }
  ];

  meta = {
    description = "D-Bus — freedesktop.org message bus system";
    homepage = "https://www.freedesktop.org/wiki/Software/dbus/";
    license = "AFL-2.1";
  };
}
