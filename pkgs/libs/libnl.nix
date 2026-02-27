##! libnl — Linux Netlink protocol library suite
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
}:
let
  version = "3.12.0";
in
mkDerivation {
  pname = "libnl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/thom311/libnl/releases/download/libnl${
        builtins.replaceStrings [ "." ] [ "_" ] version
      }/libnl-${version}.tar.gz"
    ];
    hash = "sha256-/FHKcZbxo/X99v/ThktQ9PnAIzO+KL5O7KBX4QPA3Rg=";
  };

  buildDeps = [
    gnumake
    pkg-config
    flex
    bison
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libnl-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc \
          --enable-shared \
          --disable-static
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
        pname = "lib-libnl";
        library = self;
        includes = [ "${self}/include/libnl3" ];
        libs = [ "-lnl-3" ];
        testSource = ''
          #include <netlink/netlink.h>
          #include <netlink/socket.h>
          #include <stdio.h>
          int main() {
            struct nl_sock *sk = nl_socket_alloc();
            if (!sk) return 1;
            nl_socket_free(sk);
            printf("libnl: PASS\n");
            return 0;
          }
        '';
      };
    };

  meta = {
    description = "libnl — Linux Netlink protocol library suite";
    homepage = "https://github.com/thom311/libnl";
    license = "LGPL-2.1-only";
  };
}
