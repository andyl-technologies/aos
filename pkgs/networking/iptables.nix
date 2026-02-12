# iptables — Linux packet filtering framework
{ mkDerivation, fetchurl, sources, versions, make, pkg-config, libmnl, libnftnl }:

mkDerivation {
  name = "iptables-${versions.networking.iptables}";
  version = versions.networking.iptables;

  src = fetchurl {
    inherit (sources.iptables) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl libnftnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd iptables-${versions.networking.iptables}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sbindir=$out/sbin \
          --enable-shared \
          --disable-static \
          --enable-devel \
          --enable-libipq \
          --enable-nftables
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
    description = "iptables — Linux kernel packet filtering administration";
    homepage = "https://www.netfilter.org/projects/iptables/";
    license = "GPL-2.0-or-later";
  };
}
