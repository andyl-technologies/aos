##! nftables — Netfilter tables userspace tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
  libnftnl,
  readline,
  jansson,
}: let
  version = "1.1.1";
in
  mkDerivation {
    pname = "nftables";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/nftables/files/nftables-${version}.tar.xz"
      ];
      hash = "sha256-Y1iDDzpk8x45sK1CHX2tzSQLcjQ97UjY7xO4+vIEhlo=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libmnl
      libnftnl
      readline
      jansson
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd nftables-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --disable-static \
            --disable-man-doc \
            --with-mini-gmp \
            --with-cli=readline \
            --with-json
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
      description = "nftables — packet filtering and classification framework";
      homepage = "https://www.netfilter.org/projects/nftables/";
      license = "GPL-2.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-nftables";
        tool = self;
        command = "nft --version";
      };

      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["nft"];
      };

      network-firewall-stack = testing.mkVMTest {
        name = "cross-cutting-network-firewall-stack";
        rootfsDeps = [
          pkgs.libnl
          pkgs.libmnl
          pkgs.libnftnl
        ];
        testScript = ''
          export C_INCLUDE_PATH="${pkgs.libnl}/include/libnl3:${pkgs.libmnl}/include:${pkgs.libnftnl}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${pkgs.libnl}/lib:${pkgs.libmnl}/lib:${pkgs.libnftnl}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${pkgs.libnl}/lib:${pkgs.libmnl}/lib:${pkgs.libnftnl}/lib:$LD_LIBRARY_PATH"

          cat > /tmp/netfilter_test.c << 'EOF'
          #include <netlink/netlink.h>
          #include <libmnl/libmnl.h>
          #include <libnftnl/table.h>
          #include <stdio.h>

          int main(void) {
              struct nl_sock *sk = nl_socket_alloc();
              if (!sk) {
                  fprintf(stderr, "nl_socket_alloc failed\n");
                  return 1;
              }
              printf("libnl: socket allocated OK\n");
              nl_socket_free(sk);
              printf("libnl: socket freed OK\n");

              struct mnl_socket *mnl = mnl_socket_open(NETLINK_NETFILTER);
              if (!mnl) {
                  printf("libmnl: mnl_socket_open returned NULL (expected in constrained VM)\n");
              } else {
                  printf("libmnl: socket opened OK\n");
                  mnl_socket_close(mnl);
                  printf("libmnl: socket closed OK\n");
              }

              struct nftnl_table *t = nftnl_table_alloc();
              if (!t) {
                  fprintf(stderr, "nftnl_table_alloc failed\n");
                  return 1;
              }
              nftnl_table_set_str(t, NFTNL_TABLE_NAME, "test_table");
              printf("libnftnl: table allocated and named OK\n");
              nftnl_table_free(t);
              printf("libnftnl: table freed OK\n");

              printf("Network/firewall stack: PASS\n");
              return 0;
          }
          EOF

          echo "==> Compiling netfilter stack test"
          gcc -o /tmp/netfilter_test /tmp/netfilter_test.c -lnl-3 -lmnl -lnftnl
          echo "==> Running netfilter stack test"
          /tmp/netfilter_test
        '';
      };
    };
  }
