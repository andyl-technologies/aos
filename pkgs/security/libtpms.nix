{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  autoconf,
  automake,
  libtool,
  m4,
  perl,
  openssl,
}: let
  version = "0.10.0";
in
  mkDerivation {
    pname = "libtpms";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/stefanberger/libtpms/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-bamlJ7Ovp7FHCs1M0XFXuGRsMaLH/zui38UMgbpBNCY=";
    };

    # perl provides pod2man, which libtpms uses to build its man pages.
    buildDeps = [gnumake pkg-config autoconf automake libtool m4 perl];
    runtimeDeps = [openssl];
    propagatedDeps = [openssl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libtpms-${version}
        '';
      }
      {
        # GitHub archive ships no configure — autogen.sh regenerates it.
        # ACLOCAL_PATH must reach pkg.m4 (PKG_CHECK_MODULES) and libtool's
        # LT_INIT macros, else autoreconf fails. --with-tpm2 enables the
        # TPM 2.0 personality swtpm drives.
        name = "configure";
        script = ''
          nativePkgConfig=$(dirname "$(dirname "$(command -v pkg-config)")")
          nativeLibtool=$(dirname "$(dirname "$(command -v libtoolize)")")
          export ACLOCAL_PATH="$nativePkgConfig/share/aclocal:$nativeLibtool/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          NOCONFIGURE=1 ./autogen.sh
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --with-openssl \
            --with-tpm2
        '';
      }
      {
        # libtpms bakes -Werror into AM_CFLAGS; GCC 14's -Warray-bounds
        # fires on its intentional flexible bignum scratch arrays. CFLAGS
        # is appended after AM_CFLAGS, so -Wno-error demotes them.
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES CFLAGS="-O2 -g -Wno-error"
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
      description = "TPM emulation library (TPM 1.2 + TPM 2.0) used by swtpm";
      homepage = "https://github.com/stefanberger/libtpms";
      license = "BSD-3-Clause";
    };
  }
