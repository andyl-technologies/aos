# D-Bus — Message bus system
{ mkDerivation, fetchurl, make, pkg-config }:

let version = "1.14.10"; in
mkDerivation {
  pname = "dbus";
  inherit version;

  src = fetchurl {
    urls = [
      "https://dbus.freedesktop.org/releases/dbus/dbus-${version}.tar.xz"
    ];
    hash = "sha256-uh8h0r2dM52i1KqHgMCd8y/qh5mLc9ok9Jq53x42pQ8=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd dbus-${version}
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
