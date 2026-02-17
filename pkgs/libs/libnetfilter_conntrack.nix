##! libnetfilter_conntrack — Userspace library for in-kernel connection tracking
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  libmnl,
  libnfnetlink,
}: let
  version = "1.1.0";
in
  mkDerivation {
    pname = "libnetfilter_conntrack";
    inherit version;

    src = fetchurl {
      urls = [
        "https://netfilter.org/projects/libnetfilter_conntrack/files/libnetfilter_conntrack-${version}.tar.xz"
      ];
      hash = "sha256-Z+3LTrgmwvjcmK8I2r/2jzs9D+b7fZ0Kwe5+zOD+aU4=";
    };

    buildDeps = [
      make
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [libnfnetlink];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnetfilter_conntrack-${version}
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
        pname = "lib-libnetfilter-conntrack";
        library = self;
        libs = [
          "-lnetfilter_conntrack"
          "-lnfnetlink"
          "-lmnl"
        ];
        extraDeps = [
          pkgs.libnfnetlink
          pkgs.libmnl
        ];
        testSource = ''
          #include <libnetfilter_conntrack/libnetfilter_conntrack.h>
          #include <stdio.h>
          int main() {
            struct nf_conntrack *ct = nfct_new();
            if (!ct) return 1;
            nfct_destroy(ct);
            printf("libnetfilter_conntrack: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libnetfilter_conntrack — userspace library for in-kernel connection tracking";
      homepage = "https://netfilter.org/projects/libnetfilter_conntrack/";
      license = "GPL-2.0-or-later";
    };
  }
