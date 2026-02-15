##! ethtool — Utility for querying/controlling network device driver and hardware
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  libmnl,
}:

let
  version = "6.11";
in
mkDerivation {
  pname = "ethtool";
  inherit version;

  src = fetchurl {
    urls = [
      "https://mirrors.kernel.org/pub/software/network/ethtool/ethtool-${version}.tar.xz"
    ];
    hash = "sha256-jZH1xyrj8lt+iNR4EnncsyD3HjAFiRQ3CxxXTJazEgI=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [ libmnl ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd ethtool-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sbindir=$out/sbin
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
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
