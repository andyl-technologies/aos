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
  krb5,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  perl,
  cpio,
  java-native-foundation,
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
  bootstrapJdk =
    if isDarwinCross
    then buildPackages.openjdk-8
    else buildTools.openjdk-7;
  hotspotTargetArch =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else "amd64";
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
  jnfFrameworks = "${java-native-foundation}/Library/Frameworks";
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
        bootstrapJdk
      ]
      ++ lib.optionals isDarwinCross [buildTools.python3];
    runtimeDeps =
      [zlib]
      ++ lib.optionals (!isDarwinCross) [alsa-lib]
      ++ [
        fontconfig
        freetype
        cups
      ]
      ++ lib.optionals isDarwinCross [
        krb5
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
          sed -i 's|--with-extra-asflags="$(CCASFLAGS)"|--with-extra-asflags="$(CCASFLAGS)"${lib.optionalString isDarwinCross " --with-toolchain-type=clang"} --x-includes=${xorg-stubs}/include --x-libraries=${xorg-stubs}/lib|' Makefile.in
          # Inject library paths into --with-extra-ldflags for native code linking
          sed -i 's|--with-extra-ldflags="$(LDFLAGS)"|--with-extra-ldflags="$(LDFLAGS) -L${xorg-stubs}/lib -L${freetype}/lib -L${fontconfig}/lib -L${cups}/lib${lib.optionalString (!isDarwinCross) " -L${alsaForBuild}/lib"} -L${zlib}/lib"|' Makefile.in${lib.optionalString isDarwinCross ''

            # Preserve OpenJDK 8's complete JavaNativeFoundation consumers.
            # Compile and link against the pinned source-built target framework;
            # relative runtime search paths resolve the copy bundled in the JDK.
            sed -i \
              -e 's|--with-extra-cflags="$(CFLAGS)"|--with-extra-cflags="$(CFLAGS) -F${jnfFrameworks}"|' \
              -e 's|--with-extra-cxxflags="$(CXXFLAGS)"|--with-extra-cxxflags="$(CXXFLAGS) -F${jnfFrameworks}"|' \
              -e 's|--with-extra-ldflags="$(LDFLAGS)|--with-extra-ldflags="$(LDFLAGS) -F${jnfFrameworks} -Wl,-rpath,@loader_path -Wl,-rpath,@loader_path/..|' \
              Makefile.in
          ''}
          sed -i '/ICEDTEA_COMMON_ENV = /,/LD_LIBRARY_PATH=""/{
            s|LD_LIBRARY_PATH=""|C_INCLUDE_PATH="${xorg-stubs}/include:${cups}/include:${fontconfig}/include:${freetype}/include:${freetype}/include/freetype2${lib.optionalString (!isDarwinCross) ":${alsaForBuild}/include"}:${zlib}/include" LIBRARY_PATH="${xorg-stubs}/lib:${cups}/lib:${fontconfig}/lib:${freetype}/lib${lib.optionalString (!isDarwinCross) ":${alsaForBuild}/lib"}:${zlib}/lib" FREETYPE_INCLUDE_PATH="${freetype}/include/freetype2" FREETYPE_LIB_PATH="${freetype}/lib" LD_LIBRARY_PATH=""|
          }' Makefile.in

          # No additional patches needed here
        '';
      }
      {
        name = "setup-tools";
        script =
          if isDarwinCross
          then ''
              # Create getconf wrapper (not in our glibc package)
              TOOLS=$(pwd)/tools-bin
              mkdir -p $TOOLS
              cat > $TOOLS/getconf << 'GETCONFEOF'
            #!${buildTools.bash}/bin/bash
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
            #!${buildTools.bash}/bin/bash
            echo "not a dynamic executable"
            LDDEOF
              chmod +x $TOOLS/ldd

              # OpenJDK's macOS build clears Finder/resource-fork
              # attributes from copied image files. The build itself runs
              # on Linux, so provide the same list/clear operations through
              # Python's native extended-attribute API rather than requiring
              # an ambient host xattr tool.
              cat > $TOOLS/xattr << 'XATTREOF'
            #!${buildTools.python3}/bin/python3
            import os
            import sys


            def main():
                flags = sys.argv[1] if len(sys.argv) > 1 else ""
                operations = set(flags[1:]) if flags.startswith("-") else set()
                if (
                    len(sys.argv) != 3
                    or not operations.intersection({"c", "l"})
                    or not operations.issubset({"c", "l", "s"})
                ):
                    print("usage: xattr -c|-l [-s] path", file=sys.stderr)
                    return 2

                path = sys.argv[2]
                follow_symlinks = "s" not in operations
                try:
                    names = os.listxattr(path, follow_symlinks=follow_symlinks)
                    if "l" in operations:
                        for name in names:
                            value = os.getxattr(
                                path, name, follow_symlinks=follow_symlinks
                            )
                            print(f"{name}: {value!r}")
                    else:
                        for name in names:
                            os.removexattr(
                                path, name, follow_symlinks=follow_symlinks
                            )
                except OSError as error:
                    print(f"xattr: {path}: {error}", file=sys.stderr)
                    return 1
                return 0


            if __name__ == "__main__":
                sys.exit(main())
            XATTREOF
              chmod +x $TOOLS/xattr

              # The old configure harness asks xcodebuild only for a
              # historical version gate and the active SDK path. Report
              # the real AOS SDK while retaining the expected Xcode 4
              # compatibility level; compilation still goes through the
              # AOS Darwin ccWrapper, never through Xcode tools.
              cat > $TOOLS/xcodebuild << 'XCODEBUILDEOF'
            #!${buildTools.bash}/bin/bash
            if [ "$#" -eq 1 ] && [ "$1" = "-version" ]; then
              printf '%s\n' 'Xcode 4.6.3' 'Build version 4H1503'
            elif [ "$#" -eq 3 ] && [ "$1" = "-sdk" ] && [ "$3" = "-version" ]; then
              printf 'Path: %s\n' '${stdenv.sdk}'
            else
              printf 'unsupported xcodebuild query:' >&2
              printf ' %s' "$@" >&2
              printf '\n' >&2
              exit 2
            fi
            XCODEBUILDEOF
              chmod +x $TOOLS/xcodebuild

              # HotSpot's ADLC executable is a Linux build-time generator,
              # despite being configured inside the target VM build. Keep it
              # on the native compiler and strip only target-driver state
              # which cannot apply to a Linux executable.
              cat > $TOOLS/native-cxx << 'NATIVECXXEOF'
            #!${buildTools.bash}/bin/bash
            native_hardening=
            for token in $AOS_HARDENING_ENABLE; do
              case "$token" in
                pacret) ;;
                *) native_hardening="$native_hardening $token" ;;
              esac
            done
            export AOS_HARDENING_ENABLE="$native_hardening"
            unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS SDKROOT

            native_args=()
            skip_next=false
            for arg in "$@"; do
              if $skip_next; then
                skip_next=false
                continue
              fi
              case "$arg" in
                -arch|-framework|-isysroot)
                  skip_next=true
                  ;;
                -flimit-debug-info|-Qunused-arguments|-mbranch-protection=pac-ret|-mstack-alignment=*|-mmacosx-version-min=*|-stdlib=libc++|--sysroot=*|-Wno-format)
                  ;;
                *)
                  native_args+=("$arg")
                  ;;
              esac
            done

            exec ${buildTools.cc}/bin/c++ "''${native_args[@]}"
            NATIVECXXEOF
              chmod +x $TOOLS/native-cxx
              export PATH="$TOOLS:$PATH"
          ''
          else ''
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
          export CFLAGS="-fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=incompatible-pointer-types -Wno-error=int-conversion${lib.optionalString isDarwinCross " -Wno-reserved-user-defined-literal -Wno-register"}"
          export CXXFLAGS="-fcommon -Wno-error${lib.optionalString isDarwinCross " -Wno-reserved-user-defined-literal -Wno-register"}"

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
          ${lib.optionalString (!isDarwinCross) "export ALSA_CFLAGS=\"-I${alsaForBuild}/include\"\nexport ALSA_LIBS=\"-L${alsaForBuild}/lib -lasound\""}

          $CONFIG_SHELL configure \
            ${configurePlatformFlags}--prefix=$out \
            --with-jdk-home=${bootstrapJdk} \
            --disable-docs \
            --disable-downloading \
            --disable-tests \
            --${
            if isDarwinCross
            then "disable"
            else "enable"
          }-bootstrap \
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
            ${lib.optionalString (!isDarwinCross) "--with-alsa=${alsaForBuild} "}\
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
          export CFLAGS="-fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=incompatible-pointer-types -Wno-error=int-conversion${lib.optionalString isDarwinCross " -Wno-reserved-user-defined-literal -Wno-register"} -I${xorg-stubs}/include"
          export CXXFLAGS="-fcommon -Wno-error${lib.optionalString isDarwinCross " -Wno-reserved-user-defined-literal -Wno-register"} -I${xorg-stubs}/include"
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

          ${
            if isDarwinCross
            then ''              # A cross target cannot execute the target JDK for IcedTea's self-bootstrap cycle.
                        # Use the native OpenJDK 8 as build JDK and configure the final target tree directly.''
            else "# Stage 1: Extract and configure (creates openjdk-boot/ tree)"
          }
          make -j1 stamps/icedtea-${
            if isDarwinCross
            then "configure"
            else "boot-configure"
          }.stamp${lib.optionalString isDarwinCross ''

                                   # The bundled zlib assumes classic Mac targets have no
                                   # fdopen(3) and defines it as NULL. The Darwin SDK does
                                   # provide fdopen, and Clang expands the macro while
                                   # parsing the SDK declaration unless this obsolete
                                   # fallback is removed.
                                   zutil=openjdk/jdk/src/share/native/java/util/zip/zlib/zutil.h
                       test "$(grep -c '^#      ifndef fdopen$' "$zutil")" -eq 1
                       sed -i \
                         '/#      ifndef fdopen/,/#      endif/d' \
                         "$zutil"
                       ! grep -q '^#      ifndef fdopen$' "$zutil"

                                   # Shifting a negative value is not an integer constant
                                   # expression in modern Clang. Express the same reserved
                                   # high-bit mask without undefined signed-left-shift
                                   # semantics.
                                   packConstants=openjdk/jdk/src/share/native/com/sun/java/util/jar/pack/constants.h
                                   grep -Fq 'AO_UNUSED_MBZ             = (-1)<<13' "$packConstants"
                                   sed -i \
                                     's|AO_UNUSED_MBZ             = (-1)<<13|AO_UNUSED_MBZ             = ~((1<<13)-1)|' \
                                     "$packConstants"
                                   grep -Fq 'AO_UNUSED_MBZ             = ~((1<<13)-1)' "$packConstants"

                                         # The HotSpot ADLC executable is a native build-time generator even
                                         # while the VM itself targets Darwin. IcedTea copies the target
                                       # Clang target flags into its CFLAGS, so keep those flags on target
                                       # objects but remove the Clang-only options from ADLC's native GCC
                                       # compile and link commands.
                                   sed -i \
                                     's|^HOTSPOT_MAKE_ARGS:=|HOTSPOT_MAKE_ARGS:=OS=bsd OS_VENDOR=Darwin ARCH=${hotspotTargetArch} |' \
                                     openjdk.build/hotspot-spec.gmk
                                   grep -q '^HOTSPOT_MAKE_ARGS:=OS=bsd OS_VENDOR=Darwin ARCH=${hotspotTargetArch} ' \
                                     openjdk.build/hotspot-spec.gmk

                                   # This 8u configure recognizes Clang as a toolchain but
                                   # only assigns dependency-file flags to its GCC branch.
                                   # NativeCompilation.gmk always passes the following .d
                                   # pathname, so without -MMD -MF Clang treats it as an
                                   # input file instead of creating it.
                                   printf '%s\n' \
                                     'C_FLAG_DEPS := -MMD -MF' \
                                     'CXX_FLAG_DEPS := -MMD -MF' \
                                     >> openjdk.build/spec.gmk
                                   grep -q '^C_FLAG_DEPS := -MMD -MF$' openjdk.build/spec.gmk

                                   # The 8u292 flag setup initializes shared-library flags only
                                   # for a toolchain named `gcc`, even though its Darwin Clang
                                   # support uses the same Mach-O linker contract. Restore the
                                   # upstream Darwin values in the generated target specification;
                                   # otherwise every .dylib is linked as an executable and fails
                                   # looking for `main`.
                                   jdkSpec=openjdk.build/spec.gmk
                                   grep -Fxq 'SHARED_LIBRARY_FLAGS:=' "$jdkSpec"
                                   grep -Fxq 'SET_EXECUTABLE_ORIGIN=' "$jdkSpec"
                                   grep -Fxq 'SET_SHARED_LIBRARY_ORIGIN=' "$jdkSpec"
                                   grep -Fxq 'SET_SHARED_LIBRARY_NAME=' "$jdkSpec"
                                   test "$(grep -c '^LDFLAGS_JDKLIB:=' "$jdkSpec")" -eq 1
                                   sed -i \
                                     -e 's|^SHARED_LIBRARY_FLAGS:=$|SHARED_LIBRARY_FLAGS:=-dynamiclib -compatibility_version 1.0.0 -current_version 1.0.0 -fPIC|' \
                                     -e 's|^SET_EXECUTABLE_ORIGIN=$|SET_EXECUTABLE_ORIGIN=-Xlinker -rpath -Xlinker @loader_path/.|' \
                                     -e 's|^SET_SHARED_LIBRARY_ORIGIN=$|SET_SHARED_LIBRARY_ORIGIN=$(SET_EXECUTABLE_ORIGIN)|' \
                                     -e 's|^SET_SHARED_LIBRARY_NAME=$|SET_SHARED_LIBRARY_NAME=-Xlinker -install_name -Xlinker @rpath/$1|' \
                                     -e 's|^LDFLAGS_JDKLIB:=|LDFLAGS_JDKLIB:=-dynamiclib -compatibility_version 1.0.0 -current_version 1.0.0 -fPIC |' \
                                     "$jdkSpec"
                                   grep -Fxq 'SHARED_LIBRARY_FLAGS:=-dynamiclib -compatibility_version 1.0.0 -current_version 1.0.0 -fPIC' \
                                     "$jdkSpec"
                                   grep -Fq 'LDFLAGS_JDKLIB:=-dynamiclib -compatibility_version 1.0.0 -current_version 1.0.0 -fPIC ' \
                                     "$jdkSpec"

                                   # The old Apple makefiles use ld -r as an archive substitute for
                                   # fdlibm and the static launcher. LLVM's Mach-O linker deliberately
                                   # does not implement incremental linking. Build actual archives
                                   # through the existing NativeCompilation path; every final consumer
                                   # already uses the resulting .a with all_load where required. The
                                   # macro supplies its own `rcs` output mode, so discard Darwin's
                                   # partial-link-only `-r` ARFLAGS value for these two archives.
                                   coreLibraries=openjdk/jdk/make/lib/CoreLibraries.gmk
                                   test "$(grep -c '^      LIBRARY := fdlibm,' "$coreLibraries")" -eq 1
                                   test "$(grep -Fc 'LDFLAGS := -nostdlib -r -arch x86_64,' \
                                     "$coreLibraries")" -eq 1
                                   test "$(grep -c '^      LIBRARY := jli_static,' "$coreLibraries")" -eq 1
                                   test "$(grep -Fc 'LDFLAGS := -nostdlib -r,' "$coreLibraries")" -eq 1
                                   test "$(grep -Fc '$(JDK_OUTPUTDIR)/objs/libjli_static.a: $(BUILD_LIBJLI_STATIC)' \
                                     "$coreLibraries")" -eq 1
                                   sed -i \
                                     -e 's/^      LIBRARY := fdlibm,/      STATIC_LIBRARY := fdlibm,/' \
                                     -e 's/LDFLAGS := -nostdlib -r -arch x86_64,/ARFLAGS := $(filter-out -r,$(ARFLAGS)),/' \
                                     -e 's/^      LIBRARY := jli_static,/      STATIC_LIBRARY := jli_static,/' \
                                     -e 's/LDFLAGS := -nostdlib -r,/ARFLAGS := $(filter-out -r,$(ARFLAGS)),/' \
                                     -e '/^  $(JDK_OUTPUTDIR)\/objs\/libjli_static\.a: $(BUILD_LIBJLI_STATIC)$/,+1d' \
                                     "$coreLibraries"
                                   ! grep -Fq 'LDFLAGS := -nostdlib -r' "$coreLibraries"
                                   test "$(grep -Fc 'STATIC_LIBRARY := fdlibm,' "$coreLibraries")" -eq 2
                                   test "$(grep -Fc 'STATIC_LIBRARY := jli_static,' "$coreLibraries")" -eq 2
                                   test "$(grep -Fc 'ARFLAGS := $(filter-out -r,$(ARFLAGS)),' \
                                     "$coreLibraries")" -eq 2
                                   ! grep -Fq '$(JDK_OUTPUTDIR)/objs/libjli_static.a: $(BUILD_LIBJLI_STATIC)' \
                                     "$coreLibraries"

                                   # The 8u292 BSD HotSpot makefile omits the closing conditional for
                                   # its serviceability debug-symbol list. Linux never parses this
                                   # port, but a real Darwin build must make the nesting well formed.
                                   bsdDefs=openjdk/hotspot/make/bsd/makefiles/defs.make
                                   sed -i \
                                     '/^ADD_SA_BINARIES\/sparc =/i endif # ENABLE_FULL_DEBUG_SYMBOLS=1' \
                                     "$bsdDefs"
                                   grep -q '^endif # ENABLE_FULL_DEBUG_SYMBOLS=1' "$bsdDefs"

                                   # LLVM's Linux-hosted dsymutil accepts HotSpot's implicit output
                                   # invocation, but can return successfully without materializing
                                   # the large libjvm bundle. Name the canonical Darwin bundle
                                   # explicitly and fail at its producer if it is not created.
                                   bsdVm=openjdk/hotspot/make/bsd/makefiles/vm.make
                                   sed -i \
                                     's|$(DSYMUTIL) $@|$(DSYMUTIL) -o $@.dSYM $@ \&\& test -d $@.dSYM|' \
                                     "$bsdVm"
                                   grep -q '$(DSYMUTIL) -o $@.dSYM $@ && test -d $@.dSYM' "$bsdVm"

                                   # The legacy generic export fails to select its %.dSYM directory
                                   # rule for the nested server destination during this cross build.
                                   # State the equivalent concrete rule so the real bundle produced
                                   # above is retained in the target image.
                        printf '%s\n' \
                          'ifeq ($(OS_VENDOR), Darwin)' \
                          '$(C2_BUILD_DIR)/libjvm.dylib.dSYM: $(C2_BUILD_DIR)/libjvm.dylib' \
                          >> openjdk/hotspot/make/Makefile
                        printf '\t%s\n' '$(DSYMUTIL) -o $@ $< && test -d $@' \
                          >> openjdk/hotspot/make/Makefile
                        printf '%s\n' \
                          '$(EXPORT_SERVER_DIR)/libjvm.dylib.dSYM: $(C2_BUILD_DIR)/libjvm.dylib.dSYM' \
                          >> openjdk/hotspot/make/Makefile
                        printf '\t%s\n' '$(install-dir)' >> openjdk/hotspot/make/Makefile
                        printf '%s\n' 'endif' >> openjdk/hotspot/make/Makefile

                                   # Clang 22 reports auto-detected CUDA metadata after its own
                                   # version. This legacy parser treated every line containing
                                   # "version" as a compiler version and produced invalid make
                                   # expressions, so select the canonical Clang banner explicitly.
                                   bsdGcc=openjdk/hotspot/make/bsd/makefiles/gcc.make
                                   sed -i \
                                     's/| grep version | sed/| grep "clang version" | head -1 | sed/g' \
                                     "$bsdGcc"
                                   test "$(grep -c 'grep "clang version" | head -1' "$bsdGcc")" -eq 2

                                   # ARCH selects the outer target build (`amd64`), while ADLC source
                                   # paths use HotSpot's shared CPU family (`x86`). GNU make preserves
                                   # command-line variables across submakes, so make that deliberate
                                   # inner translation override the outer selector.
                                   bsdAdlc=openjdk/hotspot/make/bsd/makefiles/adlc.make
                                   sed -i \
                                     's/^ARCH = $(Platform_arch)$/override ARCH = $(Platform_arch)/' \
                                     "$bsdAdlc"
                                   grep -q '^override ARCH = $(Platform_arch)$' "$bsdAdlc"

                                   # Clang 22 correctly rejects left-shifting signed -1 in integral
                                   # constant expressions. These are all-bits-set masks; express that
                                   # intent as unsigned arithmetic without changing their bit values.
                                   sed -i \
                                     's/((-1) << tos_state_shift)/((~0u) << tos_state_shift)/' \
                                     openjdk/hotspot/src/share/vm/oops/cpCache.hpp
                                   sed -i \
                                     's/((-1) << FIRST_TYPE)/((~0u) << FIRST_TYPE)/' \
                                     openjdk/hotspot/src/share/vm/code/dependencies.hpp
                                   ! grep -q '((-1) << tos_state_shift)' \
                                     openjdk/hotspot/src/share/vm/oops/cpCache.hpp
                                   ! grep -q '((-1) << FIRST_TYPE)' \
                                     openjdk/hotspot/src/share/vm/code/dependencies.hpp

                                   # `address` is a pointer; the historical comparison against the
                                   # boolean false was only accepted through permissive conversion.
                                   sed -i 's/if (entry == false)/if (entry == NULL)/' \
                                     openjdk/hotspot/src/share/vm/code/compiledIC.cpp
                                   grep -q 'if (entry == NULL)' \
                                     openjdk/hotspot/src/share/vm/code/compiledIC.cpp

                                   # VMError stores platform error identifiers in an int. The BSD
                                   # port's high unsigned sentinel values are intentionally observed
                                   # through that signed representation, so make the conversion
                                   # explicit where Clang 22 otherwise diagnoses narrowing in case
                                   # labels.
                                   vmError=openjdk/hotspot/src/share/vm/utilities/vmError.cpp
                                   sed -i \
                                     -e 's/case OOM_MALLOC_ERROR:/case (int)OOM_MALLOC_ERROR:/' \
                                     -e 's/case OOM_MMAP_ERROR:/case (int)OOM_MMAP_ERROR:/' \
                                     -e 's/case INTERNAL_ERROR:/case (int)INTERNAL_ERROR:/' \
                                     "$vmError"
                                   test "$(grep -c 'case (int).*_ERROR:' "$vmError")" -eq 3

                                   # Apple OpenJDK selected the system Kerberos framework for
                                   # its native credential-cache bridge. Use the complete AOS
                                   # target MIT Kerberos implementation instead; the source uses
                                   # only the public MIT krb5 and com_err APIs.
                                   nativeCcache=openjdk/jdk/src/share/native/sun/security/krb5/nativeccache.c
                                   grep -Fq '#import <Kerberos/Kerberos.h>' "$nativeCcache"
                                   sed -i \
                                     's|#import <Kerberos/Kerberos.h>|#include <krb5.h>|' \
                                     "$nativeCcache"
                                   sed -i \
                                     '/#include <krb5.h>/a #include <com_err.h>' \
                                     "$nativeCcache"
                                   grep -Fq '#include <krb5.h>' "$nativeCcache"
                                   grep -Fq '#include <com_err.h>' "$nativeCcache"

                                   securityLibraries=openjdk/jdk/make/lib/SecurityLibraries.gmk
                                   grep -Fq 'BUILD_LIBKRB5_LIBS := -framework Kerberos' \
                                     "$securityLibraries"
                                   sed -i \
                                     -e 's|BUILD_LIBKRB5_LIBS := -framework Kerberos|BUILD_LIBKRB5_LIBS := -L${krb5}/lib -lkrb5 -lk5crypto -lcom_err|' \
                                     -e 's|CFLAGS := $(CFLAGS_JDKLIB) $(KRB5_CFLAGS)|CFLAGS := $(CFLAGS_JDKLIB) -I${krb5}/include|' \
                                     "$securityLibraries"
                                   grep -Fq 'BUILD_LIBKRB5_LIBS := -L${krb5}/lib -lkrb5 -lk5crypto -lcom_err' \
                                     "$securityLibraries"
                                   grep -Fq 'CFLAGS := $(CFLAGS_JDKLIB) -I${krb5}/include' \
                                     "$securityLibraries"

                                   # ExceptionHandling.framework disappeared from the macOS SDK
                                   # after 10.8. This source tree links it from exactly two umbrella
                                   # library lists but neither imports its headers nor calls its API;
                                   # remove only those dead link edges and retain Foundation's real
                                   # Objective-C exception support.
                                   test "$(grep -R -F -- '-framework ExceptionHandling' \
                                     openjdk/jdk/make/lib | wc -l)" -eq 2
                                   ! grep -R -E 'ExceptionHandling/|NSExceptionHandler' \
                                     openjdk/jdk/src/macosx
                                   sed -i '/-framework ExceptionHandling \\/d' \
                                     openjdk/jdk/make/lib/PlatformLibraries.gmk \
                                     openjdk/jdk/make/lib/Awt2dLibraries.gmk
                                   ! grep -R -Fq -- '-framework ExceptionHandling' \
                                     openjdk/jdk/make/lib

                                   # AudioObjectPropertyElement is an unsigned ABI typedef. The
                                   # channel loop is non-negative by construction; make that checked
                                   # conversion explicit for modern C++ list-initialization rules.
                                   portsSource=openjdk/jdk/src/macosx/native/com/sun/media/sound/PLATFORM_API_MacOSX_Ports.cpp
                                   test "$(grep -Fc 'const AudioObjectPropertyAddress address = {kAudioObjectPropertyElementName, port->scope, ch};' \
                                     "$portsSource")" -eq 1
                                   sed -i \
                                     's|const AudioObjectPropertyAddress address = {kAudioObjectPropertyElementName, port->scope, ch};|const AudioObjectPropertyAddress address = {kAudioObjectPropertyElementName, port->scope, static_cast<AudioObjectPropertyElement>(ch)};|' \
                                     "$portsSource"
                                   grep -Fq 'static_cast<AudioObjectPropertyElement>(ch)' \
                                     "$portsSource"

                                   # These two umbrella imports are unused in this source
                                   # release and are absent from the corresponding current
                                   # OpenJDK files. AWTView is deliberately excluded: it calls
                                   # JRS's complex-input selector.
                                   for unusedJrsImport in \
                                     openjdk/jdk/src/macosx/native/sun/awt/AWTEvent.m \
                                     openjdk/jdk/src/macosx/native/sun/awt/AWTWindow.m; do
                                     test "$(grep -Fc '#import <JavaRuntimeSupport/JavaRuntimeSupport.h>' \
                                       "$unusedJrsImport")" -eq 1
                                     sed -i \
                                       '/#import <JavaRuntimeSupport\/JavaRuntimeSupport.h>/d' \
                                       "$unusedJrsImport"
                                     ! grep -Fq '#import <JavaRuntimeSupport/JavaRuntimeSupport.h>' \
                                       "$unusedJrsImport"
                                   done
                                   grep -Fq '#import <JavaRuntimeSupport/JavaRuntimeSupport.h>' \
                                     openjdk/jdk/src/macosx/native/sun/awt/AWTView.m

                                   # This source directly uses IOGraphics pixel-format
                                   # macros. Include their public owning header explicitly
                                   # instead of depending on historical Xcode umbrella state.
                                   graphicsDevice=openjdk/jdk/src/macosx/native/sun/awt/CGraphicsDevice.m
                                   test "$(grep -Fc '#import "ThreadUtilities.h"' \
                                     "$graphicsDevice")" -eq 1
                                   sed -i \
                                     '/#import "ThreadUtilities.h"/a #include <IOKit/graphics/IOGraphicsTypes.h>' \
                                     "$graphicsDevice"
                                   grep -Fq '#include <IOKit/graphics/IOGraphicsTypes.h>' \
                                     "$graphicsDevice"

                                   # Backport JDK-7141393's removal of the obsolete,
                                   # compile-time-disabled CARemoteLayer experiment. Keep the
                                   # JRS import: AWTView's complex-input-method path still
                                   # calls willBeHandledByComplexInputMethod.
                                   awtView=openjdk/jdk/src/macosx/native/sun/awt/AWTView.m
                                   test "$(grep -Fc '#ifdef REMOTELAYER' "$awtView")" -eq 1
                                   test "$(grep -Fc '#endif /* REMOTELAYER */' "$awtView")" -eq 1
                                   grep -Fq '[event willBeHandledByComplexInputMethod]' "$awtView"
                                   sed -i \
                                     '/#ifdef REMOTELAYER/,/#endif \/\* REMOTELAYER \*\//d' \
                                     "$awtView"
                                   ! grep -Fq 'REMOTELAYER' "$awtView"
                                   ! grep -Fq 'JRSRemotePort' "$awtView"
                                   grep -Fq '#import <JavaRuntimeSupport/JavaRuntimeSupport.h>' \
                                     "$awtView"
                                   grep -Fq '[event willBeHandledByComplexInputMethod]' "$awtView"

                                   # Apple 10.8's NSDragging.h declares these optional
                                   # methods only on NSDraggingDestination; it does not
                                   # claim NSView adopts the protocol. AWTView nevertheless
                                   # forwards to inherited implementations after a runtime
                                   # selector check. Declare that narrowly scoped dispatch
                                   # contract for modern Clang without changing the public
                                   # SDK surface or adding an implementation.
                                   ! grep -Fq '@interface NSView (AWTViewInheritedDraggingDestination)' \
                                     "$awtView"
                                   test "$(grep -Fc '#import "CGLLayer.h"' "$awtView")" -eq 1
                                   sed -i '/#import "CGLLayer.h"/a\
            \
            @interface NSView (AWTViewInheritedDraggingDestination)\
            - (NSDragOperation)draggingEntered:(id<NSDraggingInfo>)sender;\
            - (NSDragOperation)draggingUpdated:(id<NSDraggingInfo>)sender;\
            - (void)draggingExited:(id<NSDraggingInfo>)sender;\
            - (BOOL)prepareForDragOperation:(id<NSDraggingInfo>)sender;\
            - (BOOL)performDragOperation:(id<NSDraggingInfo>)sender;\
            - (void)concludeDragOperation:(id<NSDraggingInfo>)sender;\
            - (void)draggingEnded:(id<NSDraggingInfo>)sender;\
            @end' "$awtView"
                                   test "$(grep -Fc '@interface NSView (AWTViewInheritedDraggingDestination)' \
                                     "$awtView")" -eq 1
                                   test "$(grep -Fc '@end' "$awtView")" -ge 2

                                   # Backport JDK-8257148 exactly: every supported Darwin
                                   # release has press-and-hold, so the obsolete <= 10.6
                                   # probe and its removed JRSCopyOSVersion dependency must
                                   # not remain in this 8u source release.
                                   awtView=openjdk/jdk/src/macosx/native/sun/awt/AWTView.m
                                   grep -Fq '#import "OSVersion.h"' "$awtView"
                                   awtWindow=openjdk/jdk/src/macosx/native/sun/awt/AWTWindow.m
                                   grep -Fq '#import "OSVersion.h"' "$awtWindow"
                                   ! grep -Fq 'isSnowLeopardOrLower' "$awtWindow"
                                   test "$(grep -Fc 'shouldUsePressAndHold = !isSnowLeopardOrLower();' \
                                     "$awtView")" -eq 1
                                   sed -i \
                                     -e '/#import "OSVersion.h"/d' \
                                     -e '/static BOOL shouldUsePressAndHold()/,/^}/c\static BOOL shouldUsePressAndHold() {\n    return YES;\n}' \
                                     "$awtView"
                                   sed -i '/#import "OSVersion.h"/d' "$awtWindow"
                                   grep -Fq 'static BOOL shouldUsePressAndHold() {' "$awtView"
                                   grep -Fq '    return YES;' "$awtView"
                                   ! grep -Fq 'isSnowLeopardOrLower' "$awtView"
                                   ! grep -Fq '#import "OSVersion.h"' "$awtWindow"

                                   # This bundled legacy libpng groups TARGET_OS_MAC with
                                   # classic Metrowerks/Think C compilers and consequently
                                   # selects their obsolete fp.h. Modern Darwin Clang uses
                                   # the standard math.h path already present in this source.
                                   pngPrivate=openjdk/jdk/src/share/native/sun/awt/libpng/pngpriv.h
                                   test "$(grep -Fc 'defined(THINK_C) || defined(__SC__) || defined(TARGET_OS_MAC)' \
                                     "$pngPrivate")" -eq 1
                                   sed -i \
                                     's/defined(THINK_C) || defined(__SC__) || defined(TARGET_OS_MAC)/defined(THINK_C) || defined(__SC__)/' \
                                     "$pngPrivate"
                                   ! grep -Fq 'defined(TARGET_OS_MAC)' "$pngPrivate"

                                   awtLibraries=openjdk/jdk/make/lib/Awt2dLibraries.gmk
                                   test "$(grep -Ec '^[[:space:]]+OSVersion\.m \\' \
                                     "$awtLibraries")" -eq 1
                                   sed -i '/^[[:space:]]*OSVersion\.m \\/d' "$awtLibraries"
                                   ! grep -Eq '^[[:space:]]+OSVersion\.m \\' "$awtLibraries"
                                   rm -f \
                                     openjdk/jdk/src/macosx/native/sun/awt/OSVersion.h \
                                     openjdk/jdk/src/macosx/native/sun/awt/OSVersion.m

                                   # SecKeychainItemImport's input-format parameter has
                                   # always been SecExternalFormat. Fix this source typo so
                                   # modern Clang does not reject its enum and pointer types.
                                   keystoreImpl=openjdk/jdk/src/macosx/native/apple/security/KeystoreImpl.m
                                   test "$(grep -Fc 'SecExternalItemType dataType =' \
                                     "$keystoreImpl")" -eq 1
                                   sed -i \
                                     's/SecExternalItemType dataType =/SecExternalFormat dataType =/' \
                                     "$keystoreImpl"
                                   grep -Fq 'SecExternalFormat dataType =' "$keystoreImpl"
                                   ! grep -Fq 'SecExternalItemType dataType =' "$keystoreImpl"

                                   # Modern Clang diagnoses four source issues which older
                                   # Apple toolchains accepted. Preserve the intended logic,
                                   # owned-pointer lifetime, and CoreFoundation/Foundation
                                   # toll-free bridges explicitly rather than weakening the
                                   # target warning policy.
                                   systemColors=openjdk/jdk/src/macosx/native/sun/awt/CSystemColors.m
                                   grep -Fq 'if (colorIndex < (useAppleColor) ? sun_lwawt_macosx_LWCToolkit_NUM_APPLE_COLORS : java_awt_SystemColor_NUM_COLORS) {' \
                                     "$systemColors"
                                   sed -i \
                                     's/if (colorIndex < (useAppleColor) ? sun_lwawt_macosx_LWCToolkit_NUM_APPLE_COLORS : java_awt_SystemColor_NUM_COLORS) {/if (colorIndex < (useAppleColor ? sun_lwawt_macosx_LWCToolkit_NUM_APPLE_COLORS : java_awt_SystemColor_NUM_COLORS)) {/' \
                                     "$systemColors"
                                   grep -Fq 'if (colorIndex < (useAppleColor ? sun_lwawt_macosx_LWCToolkit_NUM_APPLE_COLORS : java_awt_SystemColor_NUM_COLORS)) {' \
                                     "$systemColors"

                                   imageSurface=openjdk/jdk/src/macosx/native/sun/awt/ImageSurfaceData.m
                                   test "$(grep -Fc 'if ((transparency == java_awt_Transparency_OPAQUE))' \
                                     "$imageSurface")" -eq 1
                                   sed -i \
                                     's/if ((transparency == java_awt_Transparency_OPAQUE))/if (transparency == java_awt_Transparency_OPAQUE)/' \
                                     "$imageSurface"
                                   ! grep -Fq 'if ((transparency == java_awt_Transparency_OPAQUE))' \
                                     "$imageSurface"

                                   retainedResource=openjdk/jdk/src/macosx/native/sun/awt/CFRetainedResource.m
                                   test "$(grep -Fc '#import <JavaNativeFoundation/JavaNativeFoundation.h>' \
                                     "$retainedResource")" -eq 1
                                   ! grep -Fq '#import "NSApplicationAWT.h"' "$retainedResource"
                                   sed -i \
                                     '/#import <JavaNativeFoundation\/JavaNativeFoundation.h>/a #import "NSApplicationAWT.h"' \
                                     "$retainedResource"
                                   test "$(grep -Fc '#import "NSApplicationAWT.h"' \
                                     "$retainedResource")" -eq 1
                                   test "$(grep -Fc '[NSApp postRunnableEvent:^() {' \
                                     "$retainedResource")" -eq 1
                                   sed -i \
                                     's/\[NSApp postRunnableEvent:/[(NSApplicationAWT *)NSApp postRunnableEvent:/' \
                                     "$retainedResource"
                                   grep -Fq '[(NSApplicationAWT *)NSApp postRunnableEvent:^() {' \
                                     "$retainedResource"

                                   awtFont=openjdk/jdk/src/macosx/native/sun/font/AWTFont.m
                                   test "$(grep -Fc 'free (ltc->entries[i].ptr);' "$awtFont")" -eq 1
                                   test "$(grep -Fc '[allFonts addObject:name];' "$awtFont")" -eq 1
                                   test "$(grep -Fc '[fontFamilyTable setObject:family forKey:name];' \
                                     "$awtFont")" -eq 1
                                   test "$(grep -Fc 'JNFNSToJavaString(env, fontname)' "$awtFont")" -eq 2
                                   sed -i \
                                     -e 's/free (ltc->entries\[i\].ptr);/free((void *)ltc->entries[i].ptr);/' \
                                     -e 's/\[allFonts addObject:name\];/[allFonts addObject:(NSString *)name];/' \
                                     -e 's/\[fontFamilyTable setObject:family forKey:name\];/[fontFamilyTable setObject:(NSString *)family forKey:(NSString *)name];/' \
                                     -e 's/JNFNSToJavaString(env, fontname)/JNFNSToJavaString(env, (NSString *)fontname)/' \
                                     "$awtFont"
                                   grep -Fq 'free((void *)ltc->entries[i].ptr);' "$awtFont"
                                   grep -Fq '[allFonts addObject:(NSString *)name];' "$awtFont"
                                   grep -Fq '[fontFamilyTable setObject:(NSString *)family forKey:(NSString *)name];' \
                                     "$awtFont"
                                   grep -Fq 'JNFNSToJavaString(env, (NSString *)fontname)' "$awtFont"

                                   # These cross-translation-unit contracts already exist in
                                   # the implementation, but this source snapshot omitted the
                                   # declaration/cast needed by modern Clang's type checking.
                                   awtWindowHeader=openjdk/jdk/src/macosx/native/sun/awt/AWTWindow.h
                                   test "$(grep -Fc '+ (AWTWindow *) lastKeyWindow;' \
                                     "$awtWindowHeader")" -eq 1
                                   ! grep -Fq 'getNSWindowDisplayID_AppKitThread:' "$awtWindowHeader"
                                   sed -i \
                                     '/+ (AWTWindow \*) lastKeyWindow;/a + (NSNumber *) getNSWindowDisplayID_AppKitThread:(NSWindow *)window;' \
                                     "$awtWindowHeader"
                                   test "$(grep -Fc 'getNSWindowDisplayID_AppKitThread:' \
                                     "$awtWindowHeader")" -eq 1

                                   awtWindow=openjdk/jdk/src/macosx/native/sun/awt/AWTWindow.m
                                   test "$(grep -Fc 'nsWindow.contentView.frame = contentFrame;' \
                                     "$awtWindow")" -eq 1
                                   sed -i \
                                     's/nsWindow\.contentView\.frame = contentFrame;/[(NSView *)[nsWindow contentView] setFrame:contentFrame];/' \
                                     "$awtWindow"
                                   grep -Fq '[(NSView *)[nsWindow contentView] setFrame:contentFrame];' \
                                     "$awtWindow"

                                   accessibility=openjdk/jdk/src/macosx/native/sun/awt/JavaComponentAccessibility.m
                                   test "$(grep -Fc 'AWTView *view = fView;' "$accessibility")" -eq 1
                                   sed -i 's/AWTView \*view = fView;/AWTView *view = (AWTView *)fView;/' \
                                     "$accessibility"
                                   grep -Fq 'AWTView *view = (AWTView *)fView;' "$accessibility"

                                   # This source release has 91 direct JNF consumers,
                                   # including JObjC and libsaproc. Keep every consumer and
                                   # resolve them through the real source-built framework.
                                   test "$(grep -R -l 'JavaNativeFoundation/' \
                                     openjdk/jdk/src/macosx \
                                     openjdk/hotspot/agent/src/os/bsd \
                                     | wc -l)" -eq 91

                                   for adlcMake in \
                                     openjdk-boot/hotspot/make/linux/makefiles/adlc.make \
                                     openjdk/hotspot/make/linux/makefiles/adlc.make \
                                     openjdk-boot/hotspot/make/bsd/makefiles/adlc.make \
                                     openjdk/hotspot/make/bsd/makefiles/adlc.make; do
                                       if [ -f "$adlcMake" ]; then
                                         sed -i \
                                           -e "/include .*rules.make/a override HOSTCXX = $(pwd)/tools-bin/native-cxx" \
                                           -e '/CFLAGS += $(EXTRA_CFLAGS)/a CFLAGS := $(filter-out -flimit-debug-info -Qunused-arguments -mbranch-protection=pac-ret,$(CFLAGS))' \
                                             -e '/LFLAGS += $(EXTRA_CFLAGS) $(EXTRA_LDFLAGS)/a LFLAGS := $(filter-out -flimit-debug-info -Qunused-arguments -mbranch-protection=pac-ret,$(LFLAGS))' \
                                             "$adlcMake"
                                           fi
                                         done
          ''}

          ${lib.optionalString isDarwinCross "# Native OpenJDK 8 already supplies JAXB/JAF, so retain the target Nimbus classes.\n          if false; then\n          "}# Patch BuildJaxws.gmk: add jaf_classes to bootclasspath for JAXWS
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
          fi${lib.optionalString isDarwinCross "\n          fi"}

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
          ${
            if isDarwinCross
            then ""
            else "make -j1 stamps/icedtea-boot.stamp"
          }

          # Stage 3: Configure final build (generates new spec.gmk)
          make -j1 stamps/icedtea-configure.stamp || make -j1 stamps/icedtea-stage2-configure.stamp || true${lib.optionalString isDarwinCross ''

            # IcedTea's crypto-policy check normally executes the newly built
            # JDK. A Darwin Mach-O cannot run on the Linux builder, so preserve
            # the check in two parts: validate the target image's policy and
            # class archives statically, then run the same test class with the
            # source-identical native OpenJDK 8 build JDK. Replace the original
            # target invocation fail-closed so an upstream rule change cannot
            # silently weaken this check.
            ${buildTools.python3}/bin/python3 - <<'PY'
            from pathlib import Path

            makefile = Path("Makefile")
            original = (
                "\tif [ -e $(BUILD_SDK_DIR)/bin/java ] ; then \\\n"
                "\t  $(BUILD_SDK_DIR)/bin/java -cp $(CRYPTO_CHECK_BUILD_DIR) TestCryptoLevel ; \\\n"
                "\tfi\n"
            )
            replacement = (
                "\ttest -x $(BUILD_SDK_DIR)/bin/java\n"
                "\ttest -f $(BUILD_SDK_DIR)/jre/lib/jce.jar\n"
                "\t${buildTools.unzip}/bin/unzip -Z1 $(BUILD_SDK_DIR)/jre/lib/jce.jar | "
                "${buildTools.grep}/bin/grep -Fx javax/crypto/JceSecurity.class\n"
                "\t${buildTools.unzip}/bin/unzip -Z1 $(BUILD_SDK_DIR)/jre/lib/jce.jar | "
                "${buildTools.grep}/bin/grep -Fx javax/crypto/CryptoAllPermission.class\n"
                "\ttest -f $(BUILD_SDK_DIR)/jre/lib/security/policy/unlimited/local_policy.jar\n"
                "\t${buildTools.unzip}/bin/unzip -p "
                "$(BUILD_SDK_DIR)/jre/lib/security/policy/unlimited/local_policy.jar "
                "default_local.policy | ${buildTools.grep}/bin/grep -Fq "
                "'permission javax.crypto.CryptoAllPermission;'\n"
                "\t${buildTools.grep}/bin/grep -Fx crypto.policy=unlimited "
                "$(BUILD_SDK_DIR)/jre/lib/security/java.security\n"
                "\t${bootstrapJdk}/bin/java -cp $(CRYPTO_CHECK_BUILD_DIR) TestCryptoLevel\n"
            )
            archive_original = (
                "\tif [ -e $(BUILD_SDK_DIR)/bin/java ] ; then \\\n"
                "\t  if test \"x$(INSTALL_ARCH_DIR)\" != \"xppc64\" -a \\\n"
                "\t  \"x$(INSTALL_ARCH_DIR)\" != \"xppc64le\" ; then \\\n"
                "\t    $(BUILD_SDK_DIR)/bin/java -Xshare:dump ; \\\n"
                "\t  fi ; \\\n"
                "\tfi\n"
            )
            archive_replacement = (
                # A CDS archive encodes target VM addresses and therefore can
                # only be generated by running the Mach-O VM. Keep CDS compiled
                # into the target and exercise archive generation and loading
                # with the source-identical native VM; the Darwin runtime can
                # generate its own archive when it executes on Darwin.
                "\ttest -x $(BUILD_SDK_DIR)/bin/java\n"
                "\ttest -f $(BUILD_SDK_DIR)/jre/lib/rt.jar\n"
                "\ttest -f $(BUILD_SDK_DIR)/jre/lib/server/libjvm.dylib\n"
                "\t${buildTools.grep}/bin/grep -a -Fq DumpSharedSpaces "
                "$(BUILD_SDK_DIR)/jre/lib/server/libjvm.dylib\n"
                "\t${buildTools.grep}/bin/grep -a -Fq UseSharedSpaces "
                "$(BUILD_SDK_DIR)/jre/lib/server/libjvm.dylib\n"
                "\trm -f $(abs_top_builddir)/test/native-classes.jsa\n"
                "\t${bootstrapJdk}/bin/java -XX:+UnlockDiagnosticVMOptions "
                "-XX:SharedArchiveFile=$(abs_top_builddir)/test/native-classes.jsa "
                "-Xshare:dump\n"
                "\ttest -s $(abs_top_builddir)/test/native-classes.jsa\n"
                "\t${bootstrapJdk}/bin/java -XX:+UnlockDiagnosticVMOptions "
                "-XX:SharedArchiveFile=$(abs_top_builddir)/test/native-classes.jsa "
                "-Xshare:on -version\n"
            )

            contents = makefile.read_text()
            crypto_count = contents.count(original)
            if crypto_count != 1:
                raise SystemExit(
                    "expected exactly one target check-crypto invocation, "
                    f"found {crypto_count}"
                )
            archive_count = contents.count(archive_original)
            if archive_count != 1:
                raise SystemExit(
                    "expected exactly one target CDS archive invocation, "
                    f"found {archive_count}"
                )
            contents = contents.replace(original, replacement)
            contents = contents.replace(archive_original, archive_replacement)
            makefile.write_text(contents)
            PY
          ''}

          ${lib.optionalString isDarwinCross "# The native-JDK cross build keeps the complete Nimbus implementation.\n          if false; then\n          "}# Patch nimbus and -z defs for the final build tree too
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
          done${lib.optionalString isDarwinCross "\n          fi"}
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
            test -x "$out/bin/java"
            test -x "$out/bin/javac"
            test -f "$out/jre/lib/server/libjvm.dylib"
            test -d "$out/jre/lib/server/libjvm.dylib.dSYM"
            cp -a \
              ${java-native-foundation}/Library/Frameworks/JavaNativeFoundation.framework \
              "$out/jre/lib/"
            mkdir -p "$out/share/licenses"
            cp -a \
              ${java-native-foundation}/share/licenses/java-native-foundation \
              "$out/share/licenses/"
            test "$(find "$out/share/licenses/java-native-foundation/source-notices" \
              -type f | wc -l)" -eq 31
            bundledJnf="$out/jre/lib/JavaNativeFoundation.framework/Versions/A/JavaNativeFoundation"
            test -f "$bundledJnf"

            # JNF obtains the already-running JVM through
            # `dlopen("@rpath/libjvm.dylib")`. Give the bundled framework an
            # image-relative route to this JDK's server VM; no package-store
            # path is needed at runtime. `cp -a` preserves the immutable source
            # framework's read-only mode. llvm-install-name-tool replaces the
            # Mach-O through a sibling temporary file, so both the private
            # output copy and its containing version directory must be writable.
            chmod u+w "$(dirname "$bundledJnf")" "$bundledJnf"
            ${buildTools.llvm}/bin/llvm-install-name-tool \
              -delete_rpath ${java-native-foundation}/lib \
              -add_rpath @loader_path/../../../server \
              "$bundledJnf"
            ${buildTools.llvm}/bin/llvm-otool -l "$bundledJnf" \
              | grep -q '@loader_path/../../../server'
            ! ${buildTools.llvm}/bin/llvm-otool -l "$bundledJnf" \
              | grep -Fq '${java-native-foundation}/lib'

            # dsymutil records the pre-install libjvm location in the dSYM's
            # relocation manifest. Preserve the complete symbols while making
            # that path refer to the installed binary instead of the ephemeral
            # sandbox; the manifest contains exactly this one binary-path row.
            jvmRelocations="$out/jre/lib/server/libjvm.dylib.dSYM/Contents/Resources/Relocations/x86_64/libjvm.dylib.yml"
            test -f "$jvmRelocations"
            test "$(grep -Ec "^binary-path:[[:space:]]+'/build/icedtea-3\\.19\\.0/.*/libjvm\\.dylib'$" \
              "$jvmRelocations")" -eq 1
            sed -i \
              "s|^binary-path:.*|binary-path:     '$out/jre/lib/server/libjvm.dylib'|" \
              "$jvmRelocations"
            grep -Fqx \
              "binary-path:     '$out/jre/lib/server/libjvm.dylib'" \
              "$jvmRelocations"
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
