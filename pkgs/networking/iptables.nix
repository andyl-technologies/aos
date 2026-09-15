##! iptables — Linux packet filtering framework
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libmnl,
  libnfnetlink,
  libnetfilter_conntrack,
  libnftnl,
  libpcap,
}: let
  version = "1.8.13";
in
  mkDerivation {
    pname = "iptables";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Iptables emits the equivalent nft add-rule command.";
        "files" = {};
        "input" = "An INPUT rule accepting TCP traffic to destination port 80.";
        "operation" = "Translate the legacy rule into nftables syntax.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/iptables-translate"
              "-A"
              "INPUT"
              "-p"
              "tcp"
              "--dport"
              "80"
              "-j"
              "ACCEPT"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "nft 'add rule ip filter INPUT tcp dport 80 counter accept'\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Iptables rejects the unknown protocol with status 2.";
        "files" = {};
        "input" = "An INPUT rule naming a protocol that does not exist.";
        "operation" = "Translate the malformed rule through iptables-translate.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/iptables-translate"
              "-A"
              "INPUT"
              "-p"
              "qualification-invalid"
              "-j"
              "ACCEPT"
            ];
            "exit_code" = 2;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.netfilter.org/projects/iptables/files/iptables-${version}.tar.xz"
      ];
      hash = "sha256-GvzTPano+ROs5qISZ4gWLiB+JvXV4pxlc8Dlgf/Fi5k=";
    };

    buildDeps = [
      gnumake
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
