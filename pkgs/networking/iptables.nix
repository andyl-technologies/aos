##! iptables — Linux packet filtering framework
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  flex,
  bison,
  libmnl,
  libnfnetlink,
  libnetfilter_conntrack,
  libnftnl,
  libpcap,
}: let
  version = "1.8.11";
in
  mkDerivation {
    pname = "iptables";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/iptables/files/iptables-${version}.tar.xz"
      ];
      hash = "sha256-2HMD1V74ySvK1N0/l4sm0nIBNkKwKUJXdfW60QCf57I=";
    };

    buildDeps = [
      make
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [
      libmnl
      libnfnetlink
      libnetfilter_conntrack
      libnftnl
      libpcap
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd iptables-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin \
            --enable-shared \
            --disable-static \
            --enable-devel \
            --enable-libipq \
            --enable-bpf-compiler \
            --enable-nfsynproxy \
            --enable-nftables
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
      description = "iptables — Linux kernel packet filtering administration";
      homepage = "https://www.netfilter.org/projects/iptables/";
      license = "GPL-2.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-iptables";
        tool = self;
        command = "iptables --version";
      };
    };
  }
