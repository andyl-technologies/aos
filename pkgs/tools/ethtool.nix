##! ethtool — Utility for querying/controlling network device driver and hardware
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}: let
  version = "7.1";
in
  mkDerivation {
    pname = "ethtool";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/pub/software/network/ethtool/ethtool-${version}.tar.xz"
      ];
      hash = "sha256-TXjCbtwCVbyS9LmVtf1mEI11/5Zu1GlPYCWm03C8JJY=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ethtool-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sbindir=$out/sbin
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
      description = "ethtool — utility for controlling network drivers and hardware";
      homepage = "https://mirrors.edge.kernel.org/pub/software/network/ethtool/";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-ethtool";
        tool = self;
        command = "ethtool --version";
      };
    };
  }
