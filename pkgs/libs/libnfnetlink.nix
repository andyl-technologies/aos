##! libnfnetlink — Low-level netfilter netlink communication library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.0.2";
in
  mkDerivation {
    pname = "libnfnetlink";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-${version}.tar.bz2"
      ];
      hash = "sha256-sGTHw9Qm77R4bmCo5oWbgu4vLF5J/+6mQM/k/jPLw3Y=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnfnetlink-${version}
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libnfnetlink";
        library = self;
        libs = ["-lnfnetlink"];
        testSource = ''
          #include <libnfnetlink/libnfnetlink.h>
          #include <stdio.h>
          int main() {
            /* nfnl_open may fail in sandbox; we test symbol resolution */
            struct nfnl_handle *h = nfnl_open();
            if (h) nfnl_close(h);
            printf("libnfnetlink: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libnfnetlink — low-level library for netfilter kernel/userspace communication";
      homepage = "https://www.netfilter.org/projects/libnfnetlink/";
      license = "GPL-2.0-only";
    };
  }
