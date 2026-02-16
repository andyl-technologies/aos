##! libpcap — Packet Capture Library
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  flex,
  bison,
  libnl,
}:

let
  version = "1.10.6";
in
mkDerivation {
  pname = "libpcap";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.tcpdump.org/release/libpcap-${version}.tar.gz"
    ];
    hash = "sha256-hy3REzf+GrAq2dT+4EfJ2iRNaVxt3zTi67cz79Ttiqk=";
  };

  buildDeps = [
    make
    pkg-config
    flex
    bison
  ];
  runtimeDeps = [ libnl ];
  propagatedDeps = [ libnl ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libpcap-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-pcap=linux \
          --disable-static \
          --enable-shared
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
        rm -f $out/lib/libpcap.a
      '';
    }
  ];

  meta = {
    description = "libpcap — packet capture library";
    homepage = "https://www.tcpdump.org";
    license = "BSD-3-Clause";
  };
}
