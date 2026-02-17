##! D-Bus — Message bus system
##! Note: dbus 1.14.x uses autotools, not meson (meson is 1.15.x+)
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  expat,
  libselinux,
  audit,
}: let
  version = "1.14.10";
in
  mkDerivation {
    pname = "dbus";
    inherit version;

    src = fetchurl {
      urls = [
        "https://dbus.freedesktop.org/releases/dbus/dbus-${version}.tar.xz"
      ];
      hash = "sha256-uh8h0r2dM52i1KqHgMCd8y/qh5mLc9ok9Jq53x42pQ8=";
    };

    buildDeps = [
      make
      pkg-config
    ];
    runtimeDeps = [
      expat
      libselinux
      audit
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dbus-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --localstatedir=$out/var \
            --disable-tests \
            --disable-doxygen-docs \
            --disable-xml-docs \
            --disable-systemd \
            --enable-user-session \
            --disable-apparmor \
            --enable-selinux \
            --enable-libaudit \
            --without-x
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
      description = "D-Bus — freedesktop.org message bus system";
      homepage = "https://www.freedesktop.org/wiki/Software/dbus/";
      license = "AFL-2.1";
    };
  }
