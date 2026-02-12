# nftables — Netfilter tables userspace tools
{ mkDerivation, fetchurl, sources, versions, make, pkg-config, libmnl, libnftnl }:

mkDerivation {
  name = "nftables-${versions.networking.nftables}";
  version = versions.networking.nftables;

  src = fetchurl {
    inherit (sources.nftables) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl libnftnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd nftables-${versions.networking.nftables}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sbindir=$out/sbin \
          --disable-static \
          --disable-man-doc \
          --with-mini-gmp \
          --without-cli
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
    description = "nftables — packet filtering and classification framework";
    homepage = "https://www.netfilter.org/projects/nftables/";
    license = "GPL-2.0-or-later";
  };
}
