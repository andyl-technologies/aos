# libmnl — Minimalistic Netlink library
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "libmnl-${versions.networking.libmnl}";
  version = versions.networking.libmnl;

  src = fetchurl {
    inherit (sources.libmnl) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd libmnl-${versions.networking.libmnl}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-static \
          --enable-shared
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
    description = "libmnl — minimalistic Netlink communication library";
    homepage = "https://www.netfilter.org/projects/libmnl/";
    license = "LGPL-2.1-or-later";
  };
}
