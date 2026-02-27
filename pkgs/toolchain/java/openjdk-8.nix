##! OpenJDK 8 — built via IcedTea 3.19.0 with openjdk-7 as boot JDK
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
  openjdk-7,
}:
let
  icedteaVersion = "3.19.0";

  # IcedTea 3.19.0 — build harness for OpenJDK 8
  icedteaSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/source/icedtea-${icedteaVersion}.tar.xz"
      "https://icedtea.wildebeest.org/download/source/icedtea-${icedteaVersion}.tar.xz"
    ];
    hash = "sha256-7tYeUbo1Y1sikqbmdATV4/S/fMXWm8G4H1tpsdjRtbI=";
  };

  # OpenJDK 8 sub-component sources (IcedTea 3.19.0 drops, .tar.xz format)
  openjdkSrc = fetchurl {
    urls = [ "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/openjdk.tar.xz" ];
    hash = "sha256-ydD1ZqLPnUFQoWt8aLB8ze6zF7fQVcVvZxoNPVr9a9A=";
  };
  corbaSrc = fetchurl {
    urls = [ "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/corba.tar.xz" ];
    hash = "sha256-Gbh+ArJ6cxL6CDVmAVm+5VqeiGf9ABPcNqzAV9wzEHY=";
  };
  jaxpSrc = fetchurl {
    urls = [ "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/jaxp.tar.xz" ];
    hash = "sha256-udeO7ArnEzK2HkT3G8+ZHTr2BmMCj9sQvbHEl8sYbxA=";
  };
  jaxwsSrc = fetchurl {
    urls = [ "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/jaxws.tar.xz" ];
    hash = "sha256-GXBT2T/EeK3wZFV36F/soASxSWop3A2YrMJWscm+gN0=";
  };
  jdkSrc = fetchurl {
    urls = [ "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/jdk.tar.xz" ];
    hash = "sha256-O8Pcqh+dEJ7ZkTnhEIppGWTGitkDdSFKhB/RUiqjgpw=";
  };
  langtoolsSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/langtools.tar.xz"
    ];
    hash = "sha256-C5SVDGgVOGLDFeGq5i3lipW8lIfqGXcjvLQ11sU9PyI=";
  };
  hotspotSrc = fetchurl {
    urls = [ "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/hotspot.tar.xz" ];
    hash = "sha256-okF3ETOfPBuzsyYSAi4zH+CQA3sR75jZicH6sazryrk=";
  };
  nashornSrc = fetchurl {
    urls = [ "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/nashorn.tar.xz" ];
    hash = "sha256-JFHpf+m0w9FIWRcMliHOEyMHXpf2FIiQujZEUS871pU=";
  };
in
mkDerivation {
  pname = "openjdk-8";
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
    openjdk-7
  ];
  runtimeDeps = [
    zlib
    alsa-lib
    fontconfig
    freetype
    cups
  ];
  propagatedDeps = [ ];

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
        # IcedTea 3.x expects .tar.xz drops
        mkdir -p drops
        ln -sf ${openjdkSrc} drops/openjdk.tar.xz
        ln -sf ${corbaSrc} drops/corba.tar.xz
        ln -sf ${jaxpSrc} drops/jaxp.tar.xz
        ln -sf ${jaxwsSrc} drops/jaxws.tar.xz
        ln -sf ${jdkSrc} drops/jdk.tar.xz
        ln -sf ${langtoolsSrc} drops/langtools.tar.xz
        ln -sf ${hotspotSrc} drops/hotspot.tar.xz
        ln -sf ${nashornSrc} drops/nashorn.tar.xz
      '';
    }
    {
      name = "patch-paths";
      script = ''
        # Patch hardcoded tool paths in IcedTea and OpenJDK build system
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
        # Set CFLAGS/CXXFLAGS for modern GCC compatibility
        export CFLAGS="-fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=incompatible-pointer-types -Wno-error=int-conversion"
        export CXXFLAGS="-fcommon -Wno-error"

        # Set X11 extension include path
        export CPATH="${xorg-stubs}/include:''${CPATH:-}"

        $CONFIG_SHELL configure \
          --prefix=$out \
          --with-jdk-home=${openjdk-7} \
          --disable-docs \
          --disable-downloading \
          --disable-tests \
          --enable-bootstrap \
          --enable-headless-only \
          --enable-nss \
          --with-openjdk-src-zip=${openjdkSrc} \
          --with-corba-src-zip=${corbaSrc} \
          --with-hotspot-src-zip=${hotspotSrc} \
          --with-jaxp-src-zip=${jaxpSrc} \
          --with-jaxws-src-zip=${jaxwsSrc} \
          --with-jdk-src-zip=${jdkSrc} \
          --with-langtools-src-zip=${langtoolsSrc} \
          --with-nashorn-src-zip=${nashornSrc} \
          --disable-system-zlib \
          --disable-system-jpeg \
          --disable-system-png \
          --disable-system-gif \
          --disable-system-lcms \
          --disable-system-pcsc \
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
        # After configure extracts the OpenJDK source, apply fixes for modern GCC
        find openjdk* -name '*.gmk' -o -name 'Makefile' -o -name '*.make' 2>/dev/null | while read f; do
          sed -i 's/-Werror//g' "$f" 2>/dev/null || true
        done

        # Fix sys/sysctl.h includes (deprecated/removed in modern glibc)
        find openjdk* -name '*.c' -o -name '*.cpp' -o -name '*.h' 2>/dev/null | while read f; do
          sed -i 's|#include <sys/sysctl\.h>|/* removed: sys/sysctl.h */|g' "$f" 2>/dev/null || true
        done
      '';
    }
    {
      name = "build";
      script = ''
        export CFLAGS="-fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=incompatible-pointer-types -Wno-error=int-conversion"
        export CXXFLAGS="-fcommon -Wno-error"

        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
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
    description = "OpenJDK 8 — built via IcedTea 3.19.0";
    homepage = "https://openjdk.org";
    license = "GPL-2.0-with-classpath-exception";
  };
}
