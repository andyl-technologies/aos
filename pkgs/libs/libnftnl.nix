# libnftnl — Netfilter nf_tables userspace library
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  libmnl,
}:

let
  version = "1.2.8";
in
mkDerivation {
  pname = "libnftnl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/libnftnl/files/libnftnl-${version}.tar.xz"
    ];
    hash = "sha256-N/6l1rXJsI3nkg0pjePNyULnrmSxo+i4gLLTkK5nrZU=";
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
        cd libnftnl-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
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
      '';
    }
  ];

  meta = {
    description = "libnftnl — userspace library for nf_tables Netlink communication";
    homepage = "https://www.netfilter.org/projects/libnftnl/";
    license = "GPL-2.0-or-later";
  };
}
