##! libxcrypt — Extended crypt library for DES/MD5/SHA/Blowfish password hashing
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
}: let
  version = "4.5.2";
in
  mkDerivation {
    pname = "libxcrypt";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/besser82/libxcrypt/releases/download/v${version}/libxcrypt-${version}.tar.xz"
      ];
      hash = "sha256-cVE6McAaQovM1TZ6Mv2V8RXW2sUPtbYMd51ceUKuwHE=";
    };

    buildDeps = [
      gnumake
      perl
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libxcrypt-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-hashes=strong,glibc \
            --enable-obsolete-api=no \
            --disable-failure-tokens \
            --disable-static
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
      description = "libxcrypt — extended crypt library for password hashing";
      homepage = "https://github.com/besser82/libxcrypt";
      license = "LGPL-2.1-or-later";
    };
  }
