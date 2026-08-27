##! OpenJDK 8 — built via IcedTea 3.19.0 with openjdk-7 as boot JDK
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
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
  cpio,
  openjdk-7,
  bootstrapTools,
}: let
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildTools =
    if isDarwinCross
    then buildPackages
    else {
      inherit
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
        cpio
        openjdk-7
        ;
    };
  alsaForBuild =
    if isDarwinCross
    then buildPackages.alsa-lib
    else alsa-lib;
  configurePlatformFlags =
    if isDarwinCross
    then ''      --build=${stdenv.buildPlatform.config} \
                  --host=${stdenv.hostPlatform.config} \
    ''
    else "";
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
    urls = ["https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/openjdk.tar.xz"];
    hash = "sha256-ydD1ZqLPnUFQoWt8aLB8ze6zF7fQVcVvZxoNPVr9a9A=";
  };
  corbaSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/corba.tar.xz"];
    hash = "sha256-Gbh+ArJ6cxL6CDVmAVm+5VqeiGf9ABPcNqzAV9wzEHY=";
  };
  jaxpSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/jaxp.tar.xz"];
    hash = "sha256-udeO7ArnEzK2HkT3G8+ZHTr2BmMCj9sQvbHEl8sYbxA=";
  };
  jaxwsSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/jaxws.tar.xz"];
    hash = "sha256-GXBT2T/EeK3wZFV36F/soASxSWop3A2YrMJWscm+gN0=";
  };
  jdkSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/jdk.tar.xz"];
    hash = "sha256-O8Pcqh+dEJ7ZkTnhEIppGWTGitkDdSFKhB/RUiqjgpw=";
  };
  langtoolsSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/langtools.tar.xz"
    ];
    hash = "sha256-C5SVDGgVOGLDFeGq5i3lipW8lIfqGXcjvLQ11sU9PyI=";
  };
  hotspotSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/hotspot.tar.xz"];
    hash = "sha256-okF3ETOfPBuzsyYSAi4zH+CQA3sR75jZicH6sazryrk=";
  };
  nashornSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea8/${icedteaVersion}/nashorn.tar.xz"];
    hash = "sha256-JFHpf+m0w9FIWRcMliHOEyMHXpf2FIiQujZEUS871pU=";
  };
in
  mkDerivation {
    pname = "openjdk-8";
    version = icedteaVersion;

    src = icedteaSrc;

    buildDeps =
      [
        buildTools.gnumake
        buildTools.autoconf
        buildTools.bash
        buildTools.which
        buildTools.zip
        buildTools.unzip
        buildTools.gawk
        buildTools.coreutils
        buildTools.grep
        buildTools.sed
        buildTools.pkg-config
        buildTools.binutils
        buildTools.file
        buildTools.perl
        buildTools.cpio
        xorg-stubs
        buildTools.openjdk-7
      ]
      ++ lib.optionals isDarwinCross [alsaForBuild];
    runtimeDeps =
      [zlib]
      ++ lib.optionals (!isDarwinCross) [alsa-lib]
      ++ [
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
              -e "s|/usr/bin/echo|${buildTools.coreutils}/bin/echo|g" \
              -e "s|/bin/echo|${buildTools.coreutils}/bin/echo|g" \
              -e "s|/usr/bin/find|${buildTools.coreutils}/bin/find|g" \
              -e "s|/usr/bin/grep|${buildTools.grep}/bin/grep|g" \
              -e "s|/bin/grep|${buildTools.grep}/bin/grep|g" \
              -e "s|/usr/bin/sed|${buildTools.sed}/bin/sed|g" \
              -e "s|/bin/sed|${buildTools.sed}/bin/sed|g" \
              -e "s|/usr/bin/cpio|cpio|g" \
              -e "s|/usr/bin/file|${buildTools.file}/bin/file|g" \
              -e "s|/usr/bin/readelf|${buildTools.binutils}/bin/readelf|g" \
              "$f" 2>/dev/null || true
          done

          # Patch Makefile.in: pass X11 paths to inner OpenJDK configure.
          # IcedTea doesn't forward --x-includes/--x-libraries to the inner configure.
          # Add them to ICEDTEA_CONFIGURE so both boot and final builds find X11.
          # Also inject C_INCLUDE_PATH/LIBRARY_PATH into the sanitized env.
          sed -i 's|--with-extra-asflags="$(CCASFLAGS)"|--with-extra-asflags="$(CCASFLAGS)" --x-includes=${xorg-stubs}/include --x-libraries=${xorg-stubs}/lib|' Makefile.in
          # Inject library paths into --with-extra-ldflags for native code linking
          sed -i 's|--with-extra-ldflags="$(LDFLAGS)"|--with-extra-ldflags="$(LDFLAGS) -L${xorg-stubs}/lib -L${freetype}/lib -L${fontconfig}/lib -L${cups}/lib -L${alsaForBuild}/lib -L${zlib}/lib"|' Makefile.in
          sed -i '/ICEDTEA_COMMON_ENV = /,/LD_LIBRARY_PATH=""/{
            s|LD_LIBRARY_PATH=""|C_INCLUDE_PATH="${xorg-stubs}/include:${cups}/include:${fontconfig}/include:${freetype}/include:${freetype}/include/freetype2:${alsaForBuild}/include:${zlib}/include" LIBRARY_PATH="${xorg-stubs}/lib:${cups}/lib:${fontconfig}/lib:${freetype}/lib:${alsaForBuild}/lib:${zlib}/lib" FREETYPE_INCLUDE_PATH="${freetype}/include/freetype2" FREETYPE_LIB_PATH="${freetype}/lib" LD_LIBRARY_PATH=""|
          }' Makefile.in

          # No additional patches needed here
        '';
      }
      {
        name = "setup-tools";
        script = ''
                  # Create getconf wrapper (not in our glibc package)
                  TOOLS=$(pwd)/tools-bin
                  mkdir -p $TOOLS
                  cat > $TOOLS/getconf << 'GETCONFEOF'
                  #!/bin/sh
                  case "$1" in
                    _NPROCESSORS_ONLN|NPROCESSORS_ONLN)
                      nproc 2>/dev/null || echo 1
                      ;;
                    LONG_BIT)
                      echo 64
                      ;;
                    *)
                      echo ""
                      ;;
                  esac
          GETCONFEOF
                  chmod +x $TOOLS/getconf
                  # Create ldd wrapper
                  cat > $TOOLS/ldd << 'LDDEOF'
                  #!/bin/sh
                  echo "not a dynamic executable"
          LDDEOF
                  chmod +x $TOOLS/ldd
                  export PATH="$TOOLS:$PATH"
        '';
      }
      {
        name = "configure";
        script = ''
          export PATH="$(pwd)/tools-bin:${buildTools.pkg-config}/bin:$PATH"
          # Set CFLAGS/CXXFLAGS for modern GCC compatibility
          export CFLAGS="-fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=incompatible-pointer-types -Wno-error=int-conversion"
          export CXXFLAGS="-fcommon -Wno-error"

          # Set X11 extension include path
          export CPATH="${xorg-stubs}/include:''${CPATH:-}"

          # Override pkg-config checks for X11 and other libraries
          export FREETYPE2_CFLAGS="-I${freetype}/include/freetype2 -I${freetype}/include"
          export FREETYPE2_LIBS="-L${freetype}/lib -lfreetype"
          export XPROTO_CFLAGS="-I${xorg-stubs}/include"
          export XPROTO_LIBS=" "
          export XT_CFLAGS="-I${xorg-stubs}/include"
          export XT_LIBS="-L${xorg-stubs}/lib -lXt"
          export XRENDER_CFLAGS="-I${xorg-stubs}/include"
          export XRENDER_LIBS="-L${xorg-stubs}/lib -lXrender"
          export X11_CFLAGS="-I${xorg-stubs}/include"
          export X11_LIBS="-L${xorg-stubs}/lib -lX11"
          export XCOMPOSITE_CFLAGS="-I${xorg-stubs}/include"
          export XCOMPOSITE_LIBS="-L${xorg-stubs}/lib -lXcomposite"
          export XINERAMA_CFLAGS="-I${xorg-stubs}/include"
          export XINERAMA_LIBS="-L${xorg-stubs}/lib -lXinerama"
          export XTST_CFLAGS="-I${xorg-stubs}/include"
          export XTST_LIBS="-L${xorg-stubs}/lib -lXtst"
          export ALSA_CFLAGS="-I${alsaForBuild}/include"
          export ALSA_LIBS="-L${alsaForBuild}/lib -lasound"

          $CONFIG_SHELL configure \
            ${configurePlatformFlags}--prefix=$out \
            --with-jdk-home=${buildTools.openjdk-7} \
            --disable-docs \
            --disable-downloading \
            --disable-tests \
            --enable-bootstrap \
            --enable-headless-only \
            --disable-nss \
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
            --disable-system-kerberos \
            --disable-system-gtk \
            --disable-system-gio \
            --disable-system-gconf \
            --disable-system-fontconfig \
            --disable-system-cups \
            --disable-compile-against-syscalls \
            --with-cups=${cups} \
            --with-alsa=${alsaForBuild} \
            --x-includes=${xorg-stubs}/include \
            --x-libraries=${xorg-stubs}/lib \
            --with-parallel-jobs=$NIX_BUILD_CORES
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$(pwd)/tools-bin:${buildTools.pkg-config}/bin:$PATH"

          # Fix timestamps: prevent autotools regeneration triggered by sed patches.
          # Order: .am/.ac files must be OLDER than generated .in/configure files.
          find . \( -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) 2>/dev/null | while read f; do
            touch -t 200001010000.00 "$f" 2>/dev/null || true
          done
          find . \( -name 'aclocal.m4' -o -name 'config.h.in' \) 2>/dev/null | while read f; do
            touch -t 200001010100.00 "$f" 2>/dev/null || true
          done
          find . \( -name 'configure' -o -name 'Makefile.in' \) 2>/dev/null | while read f; do
            touch -t 200001010200.00 "$f" 2>/dev/null || true
          done
          export CFLAGS="-fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=incompatible-pointer-types -Wno-error=int-conversion -I${xorg-stubs}/include"
          export CXXFLAGS="-fcommon -Wno-error -I${xorg-stubs}/include"
          export LDFLAGS="-L${xorg-stubs}/lib"

          # Apply fixes for modern GCC to OpenJDK source before building
          if [ -d openjdk ]; then
            find openjdk -name '*.gmk' -o -name 'Makefile' -o -name '*.make' 2>/dev/null | while read f; do
              sed -i 's/-Werror//g' "$f" 2>/dev/null || true
            done
            find openjdk \( -name '*.c' -o -name '*.cpp' -o -name '*.h' \) 2>/dev/null | while read f; do
              sed -i 's|#include <sys/sysctl\.h>|/* removed: sys/sysctl.h */|g' "$f" 2>/dev/null || true
            done
          fi

          # Stage 1: Extract and configure (creates openjdk-boot/ tree)
          make -j1 stamps/icedtea-boot-configure.stamp

          # Patch BuildJaxws.gmk: add jaf_classes to bootclasspath for JAXWS
          # compilation. Our OpenJDK 7 doesn't include javax.activation in rt.jar,
          # so the build system needs the separately-compiled jaf_classes.
          for gmk in openjdk-boot/jaxws/make/BuildJaxws.gmk openjdk/jaxws/make/BuildJaxws.gmk; do
            if [ -f "$gmk" ]; then
              sed -i 's|-Xbootclasspath/p:\$(OUTPUT_ROOT)/jaxp/dist/lib/classes.jar|-Xbootclasspath/p:$(OUTPUT_ROOT)/jaxp/dist/lib/classes.jar:$(JAXWS_OUTPUTDIR)/jaf_classes|' "$gmk"
            fi
          done

          # Build supplementary JAR with javax.activation + javax.xml.bind from
          # OpenJDK 8 source. Our boot JDK (OpenJDK 7) is missing these Java EE
          # classes, but the OpenJDK 8 build tools (e.g. generatenimbus) need them.
          echo "=== Building supplementary JAXB/JAF JAR for boot JDK ==="
          SUPPL_DIR=$(pwd)/supplementary-classes
          mkdir -p $SUPPL_DIR

          # Collect JAXB + JAF source files from the extracted OpenJDK 8 source
          JAXWS_SRC=""
          for tree in openjdk-boot openjdk; do
            if [ -d "$tree/jaxws/src/share" ]; then
              JAXWS_SRC="$tree/jaxws/src/share"
              break
            fi
          done

          if [ -n "$JAXWS_SRC" ]; then
            # Compile JAF classes first (JAXB depends on javax.activation)
            JAF_SOURCES=$(find "$JAXWS_SRC/jaf_classes" -name '*.java' 2>/dev/null)
            if [ -n "$JAF_SOURCES" ]; then
              ${buildTools.openjdk-7}/bin/javac -d $SUPPL_DIR -source 7 -target 7 \
                -XDignore.symbol.file $JAF_SOURCES 2>&1 || true
            fi

            # Compile JAXB classes (javax.xml.bind.*)
            JAXB_SOURCES=$(find "$JAXWS_SRC/jaxws_classes/javax/xml/bind" -name '*.java' 2>/dev/null)
            if [ -n "$JAXB_SOURCES" ]; then
              ${buildTools.openjdk-7}/bin/javac -d $SUPPL_DIR -source 7 -target 7 \
                -XDignore.symbol.file -cp $SUPPL_DIR $JAXB_SOURCES 2>&1 || true
            fi

            # Inject ALL classes (including Messages) into bootstrap rt.jar for
            # compile-time. The javac -bootclasspath points to this rt.jar.
            BOOT_RTJAR="bootstrap/boot/jre/lib/rt.jar"
            if [ -f "$BOOT_RTJAR" ]; then
              ${buildTools.openjdk-7}/bin/jar uf "$BOOT_RTJAR" -C $SUPPL_DIR .
              echo "Injected JAXB/JAF classes into $BOOT_RTJAR"
            fi

            # Disable nimbus entirely — the generator uses JAXB which has a
            # ClassCastException bug on JDK 7, and the existing nimbus source
            # files reference the generated NimbusDefaults class.
            for tree in openjdk-boot openjdk; do
              # 1. Replace nimbus generation rule with no-op touch
              gmk="$tree/jdk/make/gensrc/GensrcSwing.gmk"
              if [ -f "$gmk" ]; then
                sed -i '/generated_nimbus.*NIMBUS_SKIN_FILE/,/TOUCH.*@/{
                  /TOUCH.*@/!{
                    /generated_nimbus/!d
                  }
                  s|.*generated_nimbus.*|$(JDK_OUTPUTDIR)/gensrc/_the.generated_nimbus:|
                }' "$gmk"
                sed -i '/^$(JDK_OUTPUTDIR)\/gensrc\/_the.generated_nimbus:/a\\t$(MKDIR) -p $(@D)\n\t$(TOUCH) $@' "$gmk"
                echo "Patched $gmk to skip nimbus generation"
              fi
              # 2. Remove nimbus source files so javac doesn't try to compile them
              for nimdir in \
                "$tree/jdk/src/share/classes/javax/swing/plaf/nimbus" \
                "$tree/jdk/src/share/classes/com/sun/java/swing/plaf/nimbus"; do
                if [ -d "$nimdir" ]; then
                  rm -rf "$nimdir"
                  echo "Removed $nimdir"
                fi
              done
            done
          fi

          # Helper to remove -z defs from generated spec.gmk files.
          # Our xorg-stubs don't export all X11 symbols and some JDK native
          # libs have cross-library runtime deps resolved via dlopen.
          remove_z_defs() {
            find . -name 'spec.gmk' 2>/dev/null | while read f; do
              sed -i 's/-Xlinker -z -Xlinker defs//g; s/-Wl,-z,defs//g' "$f" 2>/dev/null || true
            done
          }

          # Stage 2: Build boot JDK (spec.gmk already generated, patch it)
          remove_z_defs
          make -j1 stamps/icedtea-boot.stamp

          # Stage 3: Configure final build (generates new spec.gmk)
          make -j1 stamps/icedtea-configure.stamp || make -j1 stamps/icedtea-stage2-configure.stamp || true

          # Patch nimbus and -z defs for the final build tree too
          for tree in openjdk; do
            gmk="$tree/jdk/make/gensrc/GensrcSwing.gmk"
            if [ -f "$gmk" ]; then
              sed -i '/generated_nimbus.*NIMBUS_SKIN_FILE/,/TOUCH.*@/{
                /TOUCH.*@/!{
                  /generated_nimbus/!d
                }
                s|.*generated_nimbus.*|$(JDK_OUTPUTDIR)/gensrc/_the.generated_nimbus:|
              }' "$gmk"
              sed -i '/^$(JDK_OUTPUTDIR)\/gensrc\/_the.generated_nimbus:/a\\t$(MKDIR) -p $(@D)\n\t$(TOUCH) $@' "$gmk"
            fi
            for nimdir in \
              "$tree/jdk/src/share/classes/javax/swing/plaf/nimbus" \
              "$tree/jdk/src/share/classes/com/sun/java/swing/plaf/nimbus"; do
              if [ -d "$nimdir" ]; then
                rm -rf "$nimdir"
                echo "Removed $nimdir (final build)"
              fi
            done
          done
          remove_z_defs

          # Stage 4: Build final JDK
          make -j1
        '';
      }
      {
        name = "install";
        script =
          if isDarwinCross
          then ''
            mkdir -p $out
            if [ -d openjdk.build/j2sdk-image ]; then
              cp -a openjdk.build/j2sdk-image/* $out/
            elif [ -d openjdk.build/images/j2sdk-image ]; then
              cp -a openjdk.build/images/j2sdk-image/* $out/
            fi
          ''
          else ''
            mkdir -p $out
            if [ -d openjdk.build/j2sdk-image ]; then
              cp -a openjdk.build/j2sdk-image/* $out/
            elif [ -d openjdk.build/images/j2sdk-image ]; then
              cp -a openjdk.build/images/j2sdk-image/* $out/
            fi

            # Patch ELF binaries with correct dynamic linker and rpath
            INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
            BT_LIB=$(dirname "$INTERP")

            # Find libstdc++ directory (nested under lib/gcc/...)
            STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
            STDCXX_DIR=""
            if [ -n "$STDCXX_FILE" ]; then
              STDCXX_DIR=$(dirname "$STDCXX_FILE")
            fi
            RPATH="$out/lib:$out/lib/amd64:$out/lib/amd64/jli:$out/jre/lib/amd64:$out/jre/lib/amd64/jli:$out/jre/lib/amd64/server:$BT_LIB"
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
