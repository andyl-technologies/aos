# iptables — Linux packet filtering framework
{ mkDerivation, fetchurl, make, pkg-config, libmnl, libnftnl }:

let version = "1.8.10"; in
mkDerivation {
  pname = "iptables";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/iptables/files/iptables-${version}.tar.xz"
    ];
    hash = "sha256-XMJVwYk1bjF9BwdVzpNx62Oht4PDRJj7jDAmTzzFnJw=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl libnftnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd iptables-${version}
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
