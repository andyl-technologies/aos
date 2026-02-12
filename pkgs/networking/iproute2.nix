# iproute2 — Linux networking utilities
{ mkDerivation, fetchurl, sources, versions, make, pkg-config, libmnl }:

mkDerivation {
  name = "iproute2-${versions.networking.iproute2}";
  version = versions.networking.iproute2;

  src = fetchurl {
    inherit (sources.iproute2) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd iproute2-${versions.networking.iproute2}
      '';
    }
    { name = "configure";
      script = ''
        ./configure --prefix=$out
      '';
    }
    { name = "build";
      script = ''
        make PREFIX=$out SBINDIR=$out/sbin -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install PREFIX=$out SBINDIR=$out/sbin
      '';
    }
  ];

  meta = {
    description = "iproute2 — Linux networking and traffic control utilities";
    homepage = "https://wiki.linuxfoundation.org/networking/iproute2";
    license = "GPL-2.0-or-later";
  };
}
