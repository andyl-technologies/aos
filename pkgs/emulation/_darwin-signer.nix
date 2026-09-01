##! darwin-signer — Linux-native ad-hoc Mach-O signer for Darwin cross builds.
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  openssl,
}: let
  libplistVersion = "2.7.0";
  libplist = mkDerivation {
    pname = "libplist-for-darwin-signing";
    version = libplistVersion;

    src = fetchurl {
      urls = [
        "https://github.com/libimobiledevice/libplist/releases/download/${libplistVersion}/libplist-${libplistVersion}.tar.bz2"
      ];
      hash = "sha256-esQjAeiWsevjxlRjR4DIK6p8tw34VU5oP/iffCZD64s=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libplist-${libplistVersion}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-shared \
            --enable-static \
            --without-cython \
            --without-tools \
            --without-tests
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
      description = "Property-list library used by the Darwin signing build tool";
      homepage = "https://libimobiledevice.org";
      license = "LGPL-2.1-or-later";
    };
  };

  version = "2.1.5-procursus7";
in
  mkDerivation {
    pname = "darwin-signer";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ProcursusTeam/ldid/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-BORhxvAnZeSPycwLaNTcNTqcRrwcTYusBpVQnRrx/14=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [openssl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ldid-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES \
            VERSION=${version} \
            LIBPLIST_INCLUDES="-I${libplist}/include" \
            LIBPLIST_LIBS="${libplist}/lib/libplist-2.0.a" \
            LIBCRYPTO_INCLUDES="-I${openssl}/include" \
            LIBCRYPTO_LIBS="-L${openssl}/lib -lcrypto"
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out
        '';
      }
    ];

    meta = {
      description = "Linux-native tool for applying ad-hoc Mach-O signatures and entitlements";
      homepage = "https://github.com/ProcursusTeam/ldid";
      license = "AGPL-3.0-only";
    };
  }
