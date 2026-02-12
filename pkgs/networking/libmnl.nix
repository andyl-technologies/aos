# libmnl — Minimalistic Netlink library
{ mkDerivation, fetchurl, make }:

let version = "1.0.5"; in
mkDerivation {
  pname = "libmnl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/libmnl/files/libmnl-${version}.tar.bz2"
    ];
    hash = "sha256-J0ubkZ7zFSv7PaOhPJUN1g1uK81UIw/+yimNA7QNBSU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd libmnl-${version}
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
