##! libnftnl — Netfilter nf_tables userspace library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}:
let
  version = "1.2.9";
in
mkDerivation {
  pname = "libnftnl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/libnftnl/files/libnftnl-${version}.tar.xz"
    ];
    hash = "sha256-6MIWJV4SnyYnBjn+53dSZWZaMbEaqSAlPD5dXWLfxLg=";
  };

  buildDeps = [
    gnumake
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

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      link = testing.mkLinkCheck {
        pname = "lib-libnftnl";
        library = self;
        libs = [
          "-lnftnl"
          "-lmnl"
        ];
        extraDeps = [ pkgs.libmnl ];
        testSource = ''
          #include <libnftnl/table.h>
          #include <stdio.h>
          int main() {
            struct nftnl_table *t = nftnl_table_alloc();
            if (!t) return 1;
            nftnl_table_free(t);
            printf("libnftnl: PASS\n");
            return 0;
          }
        '';
      };
    };

  meta = {
    description = "libnftnl — userspace library for nf_tables Netlink communication";
    homepage = "https://www.netfilter.org/projects/libnftnl/";
    license = "GPL-2.0-or-later";
  };
}
