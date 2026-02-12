# ethtool — Utility for querying/controlling network device driver and hardware
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "ethtool-${versions.kubernetes.ethtool}";
  version = versions.kubernetes.ethtool;

  src = fetchurl {
    inherit (sources.ethtool) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd ethtool-${versions.kubernetes.ethtool}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sbindir=$out/sbin
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
    description = "ethtool — utility for controlling network drivers and hardware";
    homepage = "https://mirrors.edge.kernel.org/pub/software/network/ethtool/";
    license = "GPL-2.0-only";
  };
}
