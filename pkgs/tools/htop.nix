##! htop — Interactive process viewer
{
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gnumake,
  pkg-config,
  ncurses,
  libcap,
  libnl,
  lm-sensors,
  systemd,
}: let
  version = "3.5.1";
in
  mkDerivation {
    pname = "htop";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/htop-dev/htop/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-38SgmEXpvIb0Zqci5iuPh9WQKP85aJB3/yJXpqYFBh0=";
    };

    buildDeps = [autoconf automake libtool gnumake pkg-config];
    runtimeDeps = [ncurses libcap libnl lm-sensors systemd];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd htop-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's|/usr/include/libnl3|${libnl}/include/libnl3|' configure.ac
          sed -i \
            -e 's|libnl-3.so|${libnl}/lib/libnl-3.so|' \
            -e 's|libnl-genl-3.so|${libnl}/lib/libnl-genl-3.so|' \
            linux/LibNl.c
          sed -i \
            's|"libsensors.so"|"${lm-sensors}/lib/libsensors.so"|' \
            linux/LibSensors.c
          sed -i \
            's|"libsystemd.so.0"|"${systemd}/lib/libsystemd.so.0"|' \
            linux/SystemdMeter.c
          autoreconf -fi
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --sysconfdir=/etc \
            --enable-unicode \
            --enable-affinity \
            --enable-capabilities \
            --enable-delayacct \
            --enable-sensors
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-htop";
        tool = self;
        command = "htop --version";
      };
    };

    meta = {
      description = "Interactive process viewer";
      homepage = "https://htop.dev/";
      license = "GPL-2.0-only";
      mainProgram = "htop";
    };
  }
