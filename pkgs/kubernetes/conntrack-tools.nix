# conntrack-tools — Connection tracking userspace tools
{ mkDerivation, fetchurl, sources, versions, make, pkg-config, libmnl, libnftnl }:

mkDerivation {
  name = "conntrack-tools-${versions.kubernetes.conntrack-tools}";
  version = versions.kubernetes.conntrack-tools;

  src = fetchurl {
    inherit (sources.conntrack-tools) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl libnftnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd conntrack-tools-${versions.kubernetes.conntrack-tools}
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
    description = "conntrack-tools — userspace connection tracking tools";
    homepage = "https://www.netfilter.org/projects/conntrack-tools/";
    license = "GPL-2.0-or-later";
  };
}
