##! OpenJDK 7 — first real OpenJDK, built via IcedTea 2.6.13
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  gawk,
  coreutils,
  grep,
  sed,
  pkg-config,
  zlib,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  perl,
  jamvm-2_0,
  ecj-bootstrap,
  classpath-0_99,
  ant-bootstrap,
  fastjar,
}: let
  icedteaVersion = "2.6.13";

  # IcedTea 2.6.13 — build harness for OpenJDK 7
  icedteaSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/source/icedtea-${icedteaVersion}.tar.xz"
      "https://icedtea.wildebeest.org/download/source/icedtea-${icedteaVersion}.tar.xz"
    ];
    hash = "sha256-EE6EIF0RduIX4k93B4TFPRzWZq6yOrC66KyFjlsOY/A=";
  };

  # OpenJDK 7 sub-component sources (IcedTea 2.6.x drops)
  openjdkSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/openjdk.tar.bz2"];
    hash = "sha256-FKn5Di/lwLtz3I/8yepdx20856dKDJAc/QsK4/yMZFA=";
  };
  corbaSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/corba.tar.bz2"];
    hash = "sha256-3xFUkVytMXuTVVtWP8EqytG5Ll8ocGQnNvGGt6TYDxQ=";
  };
  jaxpSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/jaxp.tar.bz2"];
    hash = "sha256-FDpblX+7AIif+dOKS/ORIYeGtqM2ZCNSee27bnmj3sw=";
  };
  jaxwsSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/jaxws.tar.bz2"];
    hash = "sha256-0+PVXW4iMcRCDTDRJPcsVmldReijmOPMe6If8qk8EoQ=";
  };
  jdkSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/jdk.tar.bz2"];
    hash = "sha256-rb2pPR6b6JRH4AlzOmyQUMbmzr2jxnSnbrvriYZiNTQ=";
  };
  langtoolsSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/langtools.tar.bz2"];
    hash = "sha256-EgNrmF+IEc2t9tW/hA+QurJfTaHMPoa6ucP278wQBVs=";
  };
  hotspotSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/hotspot.tar.bz2"];
    hash = "sha256-muPW1D/3cc8CuMeAWsDwpFf1+nAmsTNOoQhSYtPYbZ0=";
  };
in
  mkDerivation {
    pname = "openjdk-7";
    version = icedteaVersion;

    src = icedteaSrc;

    buildDeps = [
      gnumake
      autoconf
      bash
      which
      zip
      unzip
      gawk
      coreutils
      grep
      sed
      pkg-config
      binutils
      file
      perl
      xorg-stubs
      jamvm-2_0
      ecj-bootstrap
      classpath-0_99
      ant-bootstrap
      fastjar
    ];
    runtimeDeps = [
      zlib
      alsa-lib
      fontconfig
      freetype
      cups
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd icedtea-${icedteaVersion}
        '';
      }
      {
        name = "setup-drops";
        script = ''
          # IcedTea expects source tarballs in drops/
          mkdir -p drops
          ln -sf ${openjdkSrc} drops/openjdk.tar.bz2
          ln -sf ${corbaSrc} drops/corba.tar.bz2
          ln -sf ${jaxpSrc} drops/jaxp.tar.bz2
          ln -sf ${jaxwsSrc} drops/jaxws.tar.bz2
          ln -sf ${jdkSrc} drops/jdk.tar.bz2
          ln -sf ${langtoolsSrc} drops/langtools.tar.bz2
          ln -sf ${hotspotSrc} drops/hotspot.tar.bz2
        '';
      }
      {
        name = "patch-bitrot";
        script = ''
          # Fix FreeType version detection (modern freetype is 2.x not 2.2.1)
          # IcedTea 2.6.x expects older freetype API version checks
          if [ -f Makefile.am ]; then
            sed -i 's/2\.2\.1/2.10.1/g' Makefile.am 2>/dev/null || true
          fi

          # Fix xattr.h include (attr/xattr.h -> sys/xattr.h on modern systems)
          find . -name '*.c' -o -name '*.h' | while read f; do
            sed -i 's|attr/xattr\.h|sys/xattr.h|g' "$f" 2>/dev/null || true
          done
        '';
      }
      {
        name = "patch-paths";
        script = ''
          # Patch hardcoded tool paths in IcedTea and OpenJDK build system
          # IcedTea's configure and Makefiles reference /usr/bin/* and /bin/*
          for f in $(find . -name '*.in' -o -name '*.sh' -o -name 'Makefile*' -o -name 'configure*' 2>/dev/null); do
            sed -i \
              -e "s|/usr/bin/echo|${coreutils}/bin/echo|g" \
              -e "s|/bin/echo|${coreutils}/bin/echo|g" \
              -e "s|/usr/bin/find|${coreutils}/bin/find|g" \
              -e "s|/usr/bin/grep|${grep}/bin/grep|g" \
              -e "s|/bin/grep|${grep}/bin/grep|g" \
              -e "s|/usr/bin/sed|${sed}/bin/sed|g" \
              -e "s|/bin/sed|${sed}/bin/sed|g" \
              -e "s|/usr/bin/cpio|cpio|g" \
              -e "s|/usr/bin/file|${file}/bin/file|g" \
              -e "s|/usr/bin/readelf|${binutils}/bin/readelf|g" \
              "$f" 2>/dev/null || true
          done
        '';
      }
      {
        name = "configure";
        script = ''
          # Set CFLAGS/CXXFLAGS to be permissive with GCC warnings
          export CFLAGS="-fcommon -Wno-error"
          export CXXFLAGS="-fcommon -Wno-error"

          # Set X11 extension include path for headless builds
          export CPATH="${xorg-stubs}/include:''${CPATH:-}"

          $CONFIG_SHELL configure \
            --prefix=$out \
            --with-jdk-home=${jamvm-2_0} \
            --with-ecj-jar=${ecj-bootstrap}/lib/ecj.jar \
            --with-ant-home=${ant-bootstrap} \
            --with-jar=${fastjar}/bin/fastjar \
            --with-java=${jamvm-2_0}/bin/jamvm \
            --disable-docs \
            --disable-downloading \
            --disable-tests \
            --enable-bootstrap \
            --enable-headless-only \
            --with-openjdk-src-zip=${openjdkSrc} \
            --with-corba-src-zip=${corbaSrc} \
            --with-hotspot-src-zip=${hotspotSrc} \
            --with-jaxp-src-zip=${jaxpSrc} \
            --with-jaxws-src-zip=${jaxwsSrc} \
            --with-jdk-src-zip=${jdkSrc} \
            --with-langtools-src-zip=${langtoolsSrc} \
            --without-rhino \
            --disable-system-zlib \
            --disable-system-jpeg \
            --disable-system-png \
            --disable-system-gif \
            --disable-system-lcms \
            --disable-system-sctp \
            --with-cups=${cups} \
            --with-alsa=${alsa-lib} \
            --x-includes=${xorg-stubs}/include \
            --x-libraries=${xorg-stubs}/lib \
            --with-parallel-jobs=$NIX_BUILD_CORES
        '';
      }
      {
        name = "patch-openjdk-source";
        script = ''
          # After configure extracts the OpenJDK source, apply additional fixes
          # Fix -Werror flags that break with modern GCC
          find openjdk* -name '*.gmk' -o -name 'Makefile' -o -name '*.make' 2>/dev/null | while read f; do
            sed -i \
              -e 's/-Werror//g' \
              -e 's/-Wno-error//g' \
              "$f" 2>/dev/null || true
          done

          # Disable ldd verification (breaks in sandbox)
          find openjdk* -name '*.gmk' -o -name 'Makefile' -o -name '*.make' 2>/dev/null | while read f; do
            sed -i 's/ENABLE_FULL_DEBUG_SYMBOLS=1/ENABLE_FULL_DEBUG_SYMBOLS=0/g' "$f" 2>/dev/null || true
          done

          # Fix sys/sysctl.h includes (deprecated/removed in modern glibc)
          find openjdk* -name '*.c' -o -name '*.cpp' -o -name '*.h' 2>/dev/null | while read f; do
            sed -i 's|#include <sys/sysctl\.h>|/* removed: sys/sysctl.h */|g' "$f" 2>/dev/null || true
          done

          # Set up ALT_* environment variables for the OpenJDK inner build
          export ALT_CUPS_HEADERS_PATH="${cups}/include"
          export ALT_FREETYPE_HEADERS_PATH="${freetype}/include"
          export ALT_FREETYPE_LIB_PATH="${freetype}/lib"
        '';
      }
      {
        name = "build";
        script = ''
          # IcedTea Makefile orchestrates the full build
          export CFLAGS="-fcommon -Wno-error -Wno-error=format-overflow -Wno-error=implicit-function-declaration"
          export CXXFLAGS="-fcommon -Wno-error -Wno-error=format-overflow"

          # Ensure proper ALT_* variables for HotSpot build
          export ALT_CUPS_HEADERS_PATH="${cups}/include"
          export ALT_FREETYPE_HEADERS_PATH="${freetype}/include"
          export ALT_FREETYPE_LIB_PATH="${freetype}/lib"

          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out
          # IcedTea produces the JDK image in openjdk.build/
          if [ -d openjdk.build/j2sdk-image ]; then
            cp -a openjdk.build/j2sdk-image/* $out/
          elif [ -d openjdk.build/images/j2sdk-image ]; then
            cp -a openjdk.build/images/j2sdk-image/* $out/
          fi

          # Patch ELF binaries with correct dynamic linker and rpath
          INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
          BT_LIB=$(dirname "$INTERP")

          # Find libstdc++ directory (nested under lib/gcc/...)
          STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
          STDCXX_DIR=""
          if [ -n "$STDCXX_FILE" ]; then
            STDCXX_DIR=$(dirname "$STDCXX_FILE")
          fi
          RPATH="$out/lib:$out/jre/lib/amd64:$out/jre/lib/amd64/server:$BT_LIB"
          if [ -n "$STDCXX_DIR" ]; then
            RPATH="$RPATH:$STDCXX_DIR"
          fi

          for f in $out/bin/* $out/jre/bin/*; do
            if [ -f "$f" ] && [ ! -L "$f" ]; then
              patchelf --set-interpreter "$INTERP" \
                       --set-rpath "$RPATH" \
                       "$f" 2>/dev/null || true
            fi
          done

          find $out -name '*.so' -o -name '*.so.*' | while read f; do
            if [ -f "$f" ] && [ ! -L "$f" ]; then
              patchelf --set-rpath "$RPATH" \
                       "$f" 2>/dev/null || true
            fi
          done
        '';
      }
    ];

    meta = {
      description = "OpenJDK 7 — first real OpenJDK built via IcedTea 2.6.13";
      homepage = "https://openjdk.org";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
