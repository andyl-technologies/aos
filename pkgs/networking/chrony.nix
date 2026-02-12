# Chrony — NTP client and server
{ mkDerivation, fetchurl, make }:

let version = "4.6.1"; in
mkDerivation {
  pname = "chrony";
  inherit version;

  src = fetchurl {
    urls = [
      "https://chrony-project.org/releases/chrony-${version}.tar.gz"
    ];
    hash = "sha256-Vx/3P78K4wl/BgTsouALHYuy6Rr/4aNJR4X/IdYZnFw=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd chrony-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc \
          --localstatedir=$out/var \
          --with-pidfile=$out/run/chronyd.pid \
          --without-editline \
          --without-readline \
          --disable-sechash \
          --disable-nts
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install DESTDIR=""
      '';
    }
  ];

  meta = {
    description = "Chrony — versatile NTP implementation";
    homepage = "https://chrony-project.org";
    license = "GPL-2.0-only";
  };
}
