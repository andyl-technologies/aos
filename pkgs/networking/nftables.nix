# nftables — Netfilter tables userspace tools
{ mkDerivation, fetchurl, make, pkg-config, libmnl, libnftnl }:

let version = "1.1.0"; in
mkDerivation {
  pname = "nftables";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/nftables/files/nftables-${version}.tar.xz"
    ];
    hash = "sha256-7zNzKUiGxbYH7nvoLFaiW8BOdfgC+OitzVWqyR6wqiQ=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl libnftnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd nftables-${version}
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
