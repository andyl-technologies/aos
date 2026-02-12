# pkg-config — Helper tool for compiling applications and libraries
{ mkDerivation, fetchurl, make }:

let version = "0.29.2"; in
mkDerivation {
  pname = "pkg-config";
  inherit version;

  src = fetchurl {
    urls = [
      "https://pkgconfig.freedesktop.org/releases/pkg-config-${version}.tar.gz"
    ];
    hash = "sha256-b8acAWiMlFilfrmhZkyaujcszaQgoCv0Qp/mEOfn1ZE=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd pkg-config-${version}
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
