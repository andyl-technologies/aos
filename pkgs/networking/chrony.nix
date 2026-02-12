# Chrony — NTP client and server
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "chrony-${versions.networking.chrony}";
  version = versions.networking.chrony;

  src = fetchurl {
    inherit (sources.chrony) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd chrony-${versions.networking.chrony}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc \
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
        make install
      '';
    }
  ];

  meta = {
    description = "Chrony — versatile NTP implementation";
    homepage = "https://chrony-project.org";
    license = "GPL-2.0-only";
  };
}
