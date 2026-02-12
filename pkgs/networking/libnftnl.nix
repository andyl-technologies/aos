# libnftnl — Netfilter nf_tables userspace library
{ mkDerivation, fetchurl, sources, versions, make, pkg-config, libmnl }:

mkDerivation {
  name = "libnftnl-${versions.networking.libnftnl}";
  version = versions.networking.libnftnl;

  src = fetchurl {
    inherit (sources.libnftnl) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd libnftnl-${versions.networking.libnftnl}
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
    description = "libnftnl — userspace library for nf_tables Netlink communication";
    homepage = "https://www.netfilter.org/projects/libnftnl/";
    license = "GPL-2.0-or-later";
  };
}
