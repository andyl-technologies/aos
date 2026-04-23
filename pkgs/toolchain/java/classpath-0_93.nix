##! classpath-0_93 — GNU Classpath 0.93 Java standard library (last Jikes-buildable release)
{
  mkDerivation,
  fetchurl,
  gnumake,
  jikes,
  fastjar,
  pkg-config,
  zip,
}: let
  version = "0.93";
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

    buildDeps = [
      gnumake
      jikes
      fastjar
      pkg-config
      zip
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
          find . -name configure -exec sed -i 's/-Werror//g' {} +
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
            --with-fastjar=${fastjar}/bin/fastjar
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
