##! libpcap — Packet Capture Library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libnl,
}: let
  version = "1.10.6";
in
  mkDerivation {
    pname = "libpcap";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.tcpdump.org/release/libpcap-${version}.tar.gz"
      ];
      hash = "sha256-hy3REzf+GrAq2dT+4EfJ2iRNaVxt3zTi67cz79Ttiqk=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [libnl];
    propagatedDeps = [libnl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libpcap-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --with-pcap=linux \
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
          rm -f $out/lib/libpcap.a
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libpcap";
        library = self;
        libs = ["-lpcap"];
        testSource = ''
          #include <pcap/pcap.h>
          #include <stdio.h>
          int main() {
            printf("libpcap version: %s\n", pcap_lib_version());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libpcap — packet capture library";
      homepage = "https://www.tcpdump.org";
      license = "BSD-3-Clause";
    };
  }
