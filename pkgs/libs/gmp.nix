##! GMP — GNU Multiple Precision Arithmetic Library
{
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  stdenv,
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
    disallowedReferences = [stdenv.cc];

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
          ${
            if stdenv.isCross && stdenv.hostPlatform.isDarwin
            then ''
              # GMP compiles configure helpers for the build machine. Keep
              # the native compiler isolated from target-only SDK, linker,
              # and hardening flags exported by the cross stdenv.
              native_cc="$BUILD_CC"
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/cc <<EOF
              #!$CONFIG_SHELL
              unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH
              unset CPLUS_INCLUDE_PATH LIBRARY_PATH MACOSX_DEPLOYMENT_TARGET
              unset NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$native_cc" "\$@"
              EOF
              chmod +x .aos-build-tools/cc
              export CC_FOR_BUILD="$PWD/.aos-build-tools/cc"
            ''
            else ""
          }

          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Apple libtool's fallback partial link uses ld64 -r, which
              # ld64.lld does not implement. Its single-module form links
              # the same objects directly into the shared library.
              export lt_cv_apple_cc_single_mod=yes
            ''
            else ""
          }

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
