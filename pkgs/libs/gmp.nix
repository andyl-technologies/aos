##! GMP — GNU Multiple Precision Arithmetic Library
{
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  cc,
}: let
  version = "6.3.0";
in
  mkDerivation {
    pname = "gmp";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gmplib.org/download/gmp/gmp-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/gmp/gmp-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/gmp/gmp-${version}.tar.xz"
      ];
      hash = "sha256-o8K4AgG4nmhhb0rTC8Zq7kknw85Q4zkpyoGdXENTiJg=";
    };

    buildDeps = [
      gnumake
      m4
    ];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [cc];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gmp-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --enable-cxx \
            --with-pic \
            CFLAGS=-std=c99
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

          # GMP records the build compiler for diagnostic purposes. Keeping
          # its store path here would retain the complete compiler toolchain
          # in every runtime closure that uses libgmp.
          sed -i \
            -e 's|^#define __GMP_CC .*|#define __GMP_CC "cc"|' \
            -e 's|^#define __GMP_CFLAGS .*|#define __GMP_CFLAGS ""|' \
            "$out/include/gmp.h"
        '';
      }
    ];

    meta = {
      description = "GMP — GNU Multiple Precision Arithmetic Library";
      homepage = "https://gmplib.org/";
      license = "LGPL-3.0-or-later";
    };
  }
