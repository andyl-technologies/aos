##! ipmitool — in-band and network IPMI management utility
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  pkg-config,
  openssl,
  readline,
}: let
  version = "1.8.19";
in
  mkDerivation {
    pname = "ipmitool";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ipmitool/ipmitool/archive/refs/tags/IPMITOOL_1_8_19.tar.gz"
      ];
      hash = "sha256-SLAQ57zfk+TktuQ8U8f2CqaHPVdMvUWo2G+nqu66/5w=";
    };

    buildDeps = [gnumake autoconf automake libtool pkg-config];
    runtimeDeps = [openssl readline];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd ipmitool-IPMITOOL_1_8_19
        '';
      }
      {
        name = "configure";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          sed -i '/AM_CONDITIONAL(\[DOWNLOAD\]/d' configure.ac
          sed -i '/AC_MSG_WARN(\[\*\* Download is:\])/i AM_CONDITIONAL([DOWNLOAD], [test "x$DOWNLOAD" != "x"])' configure.ac
          libtoolize --copy --force
          ./bootstrap
          ./configure \
            --prefix="$out" \
            --enable-intf-open=yes \
            --enable-intf-lan=yes \
            --enable-intf-lanplus=yes \
            --enable-intf-free=no \
            --enable-intf-dbus=no \
            --enable-intf-usb=no
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

    meta = {
      description = "Command-line utility for IPMI hardware management";
      homepage = "https://github.com/ipmitool/ipmitool";
      license = "BSD-3-Clause";
    };
  }
