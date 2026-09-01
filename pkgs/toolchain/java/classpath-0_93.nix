##! classpath-0_93 — GNU Classpath 0.93 Java standard library (last Jikes-buildable release)
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  gnumake,
  jikes,
  fastjar,
  pkg-config,
  zip,
}: let
  version = "0.93";
  configurePlatformFlags = lib.optionalString (
    stdenv.isCross && stdenv.hostPlatform.isDarwin
  ) " \\\n            --build=${stdenv.buildPlatform.config} \\\n            --host=${stdenv.hostPlatform.config}";
  fastjarForBuild =
    if stdenv.isCross
    then buildPackages.fastjar
    else fastjar;
  jikesForBuild =
    if stdenv.isCross
    then buildPackages.jikes
    else jikes;
in
  mkDerivation {
    pname = "classpath-0_93";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/classpath/classpath-${version}.tar.gz"
      ];
      hash = "sha256-3y0JNhKr0j/mfpQJ2JuyqOebFmT+Ky2kDhyO1pPjKUU=";
    };

    buildDeps =
      [
        gnumake
        jikesForBuild
        fastjarForBuild
        pkg-config
        zip
      ]
      ++ lib.optionals (stdenv.isCross && stdenv.hostPlatform.isDarwin) [
        buildPackages.automake
      ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd classpath-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # Fix implicit function declarations for GCC 14 (C23 default)
          sed -i '1i #include <stdlib.h>' native/fdlibm/dtoa.c

          # Disable -Werror — old code triggers many new GCC 14 warnings
          find . -name Makefile.in -exec sed -i 's/-Werror//g' {} +
          find . -name configure -exec sed -i 's/-Werror//g' {} +${lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isDarwin) ''

            # This 2006 release predates AArch64. Refresh only config.sub; the
            # generated configure logic remains upstream and cross-aware.
            cp ${buildPackages.automake}/share/automake-*/config.sub config.sub

            # GNU Classpath's fdlibm predates AArch64 but uses the standard
            # little-endian IEEE-754 word layout on that architecture.
            sed -i '/#ifdef __alpha__/i #ifdef __aarch64__\n#define __IEEE_LITTLE_ENDIAN\n#endif\n' \
              native/fdlibm/ieeefp.h''}
        '';
      }
      {
        name = "configure";
        script = ''
          CFLAGS="-O2 -Wno-error" \
          ./configure \
            --prefix=$out \
            --disable-gtk-peer \
            --disable-gconf-peer \
            --disable-alsa \
            --disable-dssi \
            --disable-gjdoc \
            --disable-plugin \
            --disable-examples \
            --with-jikes \
            --with-fastjar=${fastjarForBuild}/bin/fastjar${configurePlatformFlags}
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
      description = "GNU Classpath 0.93 — Java standard library implementation";
      homepage = "https://www.gnu.org/software/classpath/";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
