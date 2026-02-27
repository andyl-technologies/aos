##! libmnl — Minimalistic Netlink library
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "1.0.5";
in
mkDerivation {
  pname = "libmnl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.netfilter.org/projects/libmnl/files/libmnl-${version}.tar.bz2"
    ];
    hash = "sha256-J0ubkZ7zFSv7PaOhPJUN1g1uK81UIw/+yimNA7QNBSU=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libmnl-${version}
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
        pname = "lib-libmnl";
        library = self;
        libs = [ "-lmnl" ];
        testSource = ''
          #include <libmnl/libmnl.h>
          #include <stdio.h>
          int main() {
            /* mnl_socket_open may fail in sandbox; we test symbol resolution */
            struct mnl_socket *nl = mnl_socket_open(0);
            if (nl) mnl_socket_close(nl);
            printf("libmnl: PASS\n");
            return 0;
          }
        '';
      };
    };

  meta = {
    description = "libmnl — minimalistic Netlink communication library";
    homepage = "https://www.netfilter.org/projects/libmnl/";
    license = "LGPL-2.1-or-later";
  };
}
