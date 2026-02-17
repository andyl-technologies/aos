##! Chrony — NTP client and server
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
  libcap,
  libseccomp,
  pkg-config,
}: let
  version = "4.8";
in
  mkDerivation {
    pname = "chrony";
    inherit version;

    src = fetchurl {
      urls = [
        "https://chrony-project.org/releases/chrony-${version}.tar.gz"
      ];
      hash = "sha256-M+qOsqTa6qUG6Pyv1dbYkCftby8GCWRcbxSbVg0wFwY=";
    };

    buildDeps = [
      make
      pkg-config
    ];
    runtimeDeps = [
      openssl
      libcap
      libseccomp
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd chrony-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sysconfdir=/etc \
            --localstatedir=$out/var \
            --with-pidfile=/run/chrony/chronyd.pid \
            --without-editline \
            --without-readline \
            --disable-nts
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
          make install DESTDIR=""
        '';
      }
    ];

    meta = {
      description = "Chrony — versatile NTP implementation";
      homepage = "https://chrony-project.org";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-chrony";
        tool = self;
        command = "chronyd --version";
      };
    };
  }
