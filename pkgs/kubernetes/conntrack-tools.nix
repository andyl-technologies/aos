# conntrack-tools — Connection tracking userspace tools
{ mkDerivation, fetchurl, make, pkg-config, libmnl, libnftnl }:

let version = "1.4.8"; in
mkDerivation {
  pname = "conntrack-tools";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-${version}.tar.xz"
    ];
    hash = "sha256-BnZ39MX2VkgZ547TqdSomAk16pJz86uyKkIOowq13tY=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libmnl libnftnl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd conntrack-tools-${version}
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
