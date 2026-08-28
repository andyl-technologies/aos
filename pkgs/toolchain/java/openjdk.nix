##! OpenJDK 25 — Java Development Kit built from source
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
  zlib,
  krb5,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  openjdk-24,
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
        binutils
        file
        ;
    };
  bootJdk =
    if isDarwinCross
    then buildPackages.openjdk-24
    else openjdk-24;
  nativeMig =
    if isDarwinCross
    then
      import ./_darwin-mig.nix {
        inherit fetchurl buildPackages;
      }
    else null;
  version = "25.0.2";
  build = "10";
  tag = "jdk-${version}+${build}";
in
  mkDerivation {
    pname = "openjdk";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/openjdk/jdk25u/archive/refs/tags/${tag}.tar.gz"
      ];
      hash = "sha256-mzFkzt9416dqWUmdemgzFFx+Amnse2ZL/l7gPO0vRJ4=";
    };

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
        buildTools.binutils
        buildTools.file
        xorg-stubs
      ]
      ++ lib.optionals isDarwinCross [
        nativeMig
        buildTools.python3
        buildTools.openjdk
      ];
    runtimeDeps =
      [
        zlib
        fontconfig
        freetype
      ]
      ++ lib.optionals isDarwinCross [krb5];
    propagatedDeps = [];

    patches = [
      ./openjdk-patches/fix-java-home-jdk21.patch
      ./openjdk-patches/read-truststore-from-env-jdk10.patch
      ./openjdk-patches/increase-javadoc-heap-jdk13.patch
      ./openjdk-patches/ignore-LegalNoticeFilePlugin-jdk18.patch
    ];
    postPatch = ''
      # Fix ambiguous fma() → float call in mulnode.cpp (GCC 14)
      sed -i 's/return TypeH::make(fma(f1, f2, f3))/return TypeH::make((float)fma(f1, f2, f3))/' src/hotspot/share/opto/mulnode.cpp
    '';

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jdk25u-jdk-*
        '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
                        # These sources use public Darwin APIs without including their
                        # owning headers. Make those dependencies explicit instead of
                        # relying on Xcode's precompiled-header or umbrella accidents.
                        graphicsDevice=src/java.desktop/macosx/native/libawt_lwawt/awt/CGraphicsDevice.m
                        test "$(grep -Fc '#import "LWCToolkit.h"' "$graphicsDevice")" -eq 1
                        sed -i \
                          '/#import "LWCToolkit.h"/a #include <IOKit/graphics/IOGraphicsTypes.h>' \
                          "$graphicsDevice"
                        grep -Fq '#include <IOKit/graphics/IOGraphicsTypes.h>' \
                          "$graphicsDevice"

                        threadUtilities=src/java.desktop/macosx/native/libosxapp/ThreadUtilities.m
                        test "$(grep -Fc '#import <objc/message.h>' "$threadUtilities")" -eq 1
                        sed -i '/#import <objc\/message.h>/a #include <Block.h>' \
                          "$threadUtilities"
                        grep -Fq '#include <Block.h>' "$threadUtilities"

                        # Apple Kerberos is an MIT krb5 ABI. Use the target AOS krb5
                        # headers and libraries while retaining the native credential-
                        # cache feature and the upstream implementation.
                        nativeCcache=src/java.security.jgss/macosx/native/libosxkrb5/nativeccache.c
                        test "$(grep -Fc '#import <Kerberos/Kerberos.h>' "$nativeCcache")" -eq 1
                        sed -i \
                          's|#import <Kerberos/Kerberos.h>|#include <krb5.h>|' \
                          "$nativeCcache"
                        sed -i '/#include <krb5.h>/a #include <com_err.h>' "$nativeCcache"
                        grep -Fq '#include <krb5.h>' "$nativeCcache"
                        grep -Fq '#include <com_err.h>' "$nativeCcache"

                        krb5Gmk=make/modules/java.security.jgss/Lib.gmk
                        test "$(grep -Fc '            -framework Kerberos \' "$krb5Gmk")" -eq 1
                        sed -i \
                          's|            -framework Kerberos \\|            -L${krb5}/lib -lkrb5 -lk5crypto -lcom_err \\|' \
                          "$krb5Gmk"
                        grep -Fq \
                          '            -L${krb5}/lib -lkrb5 -lk5crypto -lcom_err \' \
                          "$krb5Gmk"

                        # flags-cflags computes OS definitions once from the Darwin target,
                        # then reuses them while compiling the native Linux BuildJDK. Keep
                        # the upstream build/target source split and correct the build-side
                        # definitions before its BUILD flag set is materialized.
                        flagsCflags=make/autoconf/flags-cflags.m4
                        sed -i \
                          '/^  FLAGS_SETUP_CFLAGS_CPU_DEP(\[BUILD\], \[OPENJDK_BUILD_\], \[BUILD_\])$/i\
              if test "x$OPENJDK_BUILD_OS" = xlinux; then\
                CFLAGS_OS_DEF_JVM="-DLINUX -D_FILE_OFFSET_BITS=64"\
                CFLAGS_OS_DEF_JDK="-D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64 -DLINUX"\
              else\
                AC_MSG_ERROR([AOS Darwin cross BuildJDK requires a Linux build OS])\
              fi\
            ' "$flagsCflags"
            test "$(grep -c 'AOS Darwin cross BuildJDK requires' "$flagsCflags")" -eq 1

            # OpenJDK generates its C++ precompiled header with CC plus
            # `-x c++-header`. AOS intentionally gives the CXX wrapper the
            # target libc++ isolation flags, so select that equivalent driver
            # role instead of falling through into native LLVM's libc++.
            pchGmk=make/common/native/CompileFile.gmk
            sed -i \
              's/$1_PCH_COMMAND := $$($1_CC)/$1_PCH_COMMAND := $$($1_CXX)/' \
              "$pchGmk"
            grep -q '^        $1_PCH_COMMAND := $$($1_CXX)' "$pchGmk"

            # The HotSpot serviceability-agent generator consumes XNU's MIG
            # definition source, which is not a public SDK header. Use the
            # exact pinned XNU source bundled with the native MIG helper.
            saGensrc=make/modules/jdk.hotspot.agent/Gensrc.gmk
            test "$(grep -Fc '$(SYSROOT)/usr/include/mach/mach_exc.defs' \
              "$saGensrc")" -eq 2
            sed -i \
              's|$(SYSROOT)/usr/include/mach/mach_exc.defs|${nativeMig}/share/mig/mach/mach_exc.defs|g' \
              "$saGensrc"
            test "$(grep -Fc '${nativeMig}/share/mig/mach/mach_exc.defs' \
              "$saGensrc")" -eq 2

            # AOS deliberately builds the existing headless JDK variant. The
                        # macOS port otherwise probes Xcode's proprietary Metal tools and
                        # builds libosxui even when headless-only is enabled. Gate both
                        # together so this feature boundary is honored without fake tools.
                        toolchainM4=make/autoconf/toolchain.m4
                        clientLibraries=make/modules/java.desktop/lib/ClientLibraries.gmk
                        sed -i \
                          '/^    UTIL_LOOKUP_TOOLCHAIN_PROGS(METAL, metal)$/i\    if test "x$ENABLE_HEADLESS_ONLY" = "xfalse"; then' \
                          "$toolchainM4"
                        sed -i \
                          '/^    UTIL_LOOKUP_TOOLCHAIN_PROGS(METALLIB, metallib)$/,/^  fi$/{
                            /^  fi$/i\    fi
                          }' \
                          "$toolchainM4"
                        grep -q '^    if test "x$ENABLE_HEADLESS_ONLY" = "xfalse"; then$' \
                          "$toolchainM4"
                        sed -i \
                          's/^ifeq ($(call isTargetOs, macosx), true)$/ifeq ($(call isTargetOs, macosx)+$(ENABLE_HEADLESS_ONLY), true+false)/' \
                          "$clientLibraries"
                        grep -q '^ifeq ($(call isTargetOs, macosx)+$(ENABLE_HEADLESS_ONLY), true+false)$' \
                          "$clientLibraries"

                        # Apple SDKs historically supplied the CUPS headers directly,
                        # so the macOS libawt_lwawt rule does not consume the CUPS flags
                        # that configure already discovered. The sparse AOS SDK keeps
                        # this open-source interface as an explicit package dependency.
                        awtLibraries=make/modules/java.desktop/lib/AwtLibraries.gmk
                        test "$(grep -Fc '      NAME := awt_lwawt, \' \
                          "$awtLibraries")" -eq 1
                        sed -i \
                          '/^      NAME := awt_lwawt, \\$/a\      CFLAGS := $(CUPS_CFLAGS), \\' \
                          "$awtLibraries"
                        test "$(grep -Fc '      CFLAGS := $(CUPS_CFLAGS), \' \
                          "$awtLibraries")" -eq 1

                        # ExceptionHandling.framework has no source-level users in this
                        # release (all matches are these two inherited linker flags), and
                        # is absent from current public SDKs. Remove only the unused flags
                        # rather than inventing an ABI-only framework.
                        test "$(grep -R -F --include='*.[chm]' \
                          --include='*.mm' -c 'ExceptionHandling' src \
                          | awk -F: '{ total += $2 } END { print total + 0 }')" -eq 0
                        test "$(grep -R -F --include='*.gmk' -c \
                          '          -framework ExceptionHandling \' make \
                          | awk -F: '{ total += $2 } END { print total + 0 }')" -eq 2
                        find make -name '*.gmk' -exec sed -i \
                          '/^[[:space:]]*-framework ExceptionHandling \\$/d' {} +
                        ! grep -R -Fq --include='*.gmk' \
                          '          -framework ExceptionHandling \' make

                        # OpenJDK clears Finder/resource-fork attributes from copied
                        # image files. The build runs on Linux, so implement the same
                        # list/clear operations through Python's native xattr API.
                        darwinTools=$TMPDIR/darwin-tools
                        mkdir -p "$darwinTools"
                        cat > "$darwinTools/xattr" <<'EOF'
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
            EOF
                        chmod +x "$darwinTools/xattr"

                        # OpenJDK marks its .app directories with Finder's bundle bit.
                        # Nix's Linux store serialization cannot represent macOS
                        # FinderInfo xattrs, while the complete .app directory layout is
                        # retained. Accept only that non-serializable metadata operation;
                        # fail closed if a future build needs any other SetFile behavior.
                        cat > "$darwinTools/SetFile" <<'EOF'
            #!${buildTools.bash}/bin/bash
            if [ "$#" -ne 3 ] || [ "$1" != "-a" ] || [ "$2" != "B" ]; then
              printf '%s\n' 'SetFile: only -a B <directory> is supported' >&2
              exit 2
            fi
            if [ ! -d "$3" ]; then
              printf 'SetFile: not a directory: %s\n' "$3" >&2
              exit 1
            fi
            exit 0
            EOF
                        chmod +x "$darwinTools/SetFile"

                        # OpenJDK requires its native BuildC compiler to match the target
                        # Clang toolchain. Wrap AOS Clang with the same hermetic glibc and
                        # GCC discovery that the native cc wrapper supplies to GCC.
                        for compiler in clang clang++; do
                          cat > "$darwinTools/build-$compiler" <<EOF
            #!${buildTools.bash}/bin/bash
            set -eu
            real_libc=\$(cat ${buildTools.bootstrapTools}/nix-support/orig-libc)
            real_libc_dev=\$(cat ${buildTools.bootstrapTools}/nix-support/orig-libc-dev)
            dynamic_linker=\$(cat ${buildTools.bootstrapTools}/nix-support/dynamic-linker)
            gcc_dir=\$(dirname "\$(${buildTools.gcc}/bin/gcc -print-libgcc-file-name)")
            linking=true
            for arg in "\$@"; do
              case "\$arg" in
                -c|-E|-S|-fsyntax-only) linking=false ;;
              esac
            done
            link_flags=()
            if \$linking; then
              link_flags=(
                -L"\$real_libc/lib"
                -Wl,-dynamic-linker="\$dynamic_linker"
                -Wl,-rpath,"\$real_libc/lib"
              )
            fi
            exec ${buildTools.llvm}/bin/$compiler \
              --gcc-install-dir="\$gcc_dir" \
              -idirafter "\$real_libc_dev/include" \
              -B"\$real_libc/lib" -B"\$gcc_dir" \
              "\''${link_flags[@]}" "\$@"
            EOF
                          chmod +x "$darwinTools/build-$compiler"
                        done

                        # LLVM supplies native inspectors/editors for emitted Mach-O files.
                        ln -s ${buildTools.llvm}/bin/llvm-otool "$darwinTools/otool"
                        ln -s ${buildTools.llvm}/bin/llvm-install-name-tool \
                          "$darwinTools/install_name_tool"
                        export PATH="$darwinTools:$PATH"

                        # The cross stdenv's global C++ search path describes the Darwin
                        # target. It must not leak into BuildJDK/ADLC, while target c++
                        # already receives its libc++ headers from the cc wrapper.
                        export CPLUS_INCLUDE_PATH=

                        # The native stdenv records -rpath-link for ELF linkers. Darwin's
                        # ld64 has no equivalent option, so retain the target library
                        # rpaths while removing only that Linux-specific search hint.
                        darwinLdflags=
                        for flag in ''${NIX_LDFLAGS:-}; do
                          case "$flag" in
                            -Wl,-rpath-link,*) ;;
                            *) darwinLdflags="$darwinLdflags $flag" ;;
                          esac
                        done

                        # Build tools and both JDK inputs execute on Linux, but the
                        # emitted image is Darwin. Use AOS's source-identical native
                        # OpenJDK 25 as the external BuildJDK: the upstream internal
                        # BuildJDK path reuses target linker modes while producing ELF.
                        # OpenJDK selects CoreAudio for this target, so an ALSA path would
                        # both misconfigure audio and pull Linux code into the closure.
                        $CONFIG_SHELL configure \
                          BUILD_CC=$darwinTools/build-clang \
                          BUILD_CXX=$darwinTools/build-clang++ \
                          --openjdk-target=${stdenv.hostPlatform.config} \
                          --with-toolchain-type=clang \
                          --with-boot-jdk=${bootJdk} \
                          --with-build-jdk=${buildTools.openjdk} \
                          --enable-headless-only \
                          --with-native-debug-symbols=none \
                          --disable-warnings-as-errors \
                          --with-zlib=system \
                          --with-libjpeg=bundled \
                          --with-giflib=bundled \
                          --with-libpng=bundled \
                          --with-lcms=bundled \
                          --with-freetype=bundled \
                          --with-cups-include=${cups}/include \
                          --x-includes=${xorg-stubs}/include \
                          --x-libraries=${xorg-stubs}/lib \
                          --with-version-build=${build} \
                          --with-version-opt=aos \
                          --with-version-pre= \
                          --with-extra-cflags="-Wno-error -fcommon" \
                          --with-extra-cxxflags="-Wno-error" \
                          --with-extra-ldflags="$darwinLdflags" \
                          --with-jobs=$NIX_BUILD_CORES
                        grep -q '^ENABLE_HEADLESS_ONLY := true$' build/*/spec.gmk
                        grep -q '^CREATE_BUILDJDK := false$' build/*/spec.gmk
                        grep -q '^EXTERNAL_BUILDJDK := true$' build/*/spec.gmk
                        grep -Fq \
                          'BUILD_JDK := ${buildTools.openjdk}' \
                          build/*/spec.gmk
          ''
          else ''
            # OpenJDK configure requires bash
            $CONFIG_SHELL configure \
              --with-boot-jdk=${openjdk-24} \
              --enable-headless-only \
              --with-native-debug-symbols=none \
              --disable-warnings-as-errors \
              --with-zlib=system \
              --with-libjpeg=bundled \
              --with-giflib=bundled \
              --with-libpng=bundled \
              --with-lcms=bundled \
              --with-cups-include=${cups}/include \
              --with-alsa=${alsa-lib} \
              --with-freetype-include=${freetype}/include/freetype2 \
              --with-freetype-lib=${freetype}/lib \
              --x-includes=${xorg-stubs}/include \
              --x-libraries=${xorg-stubs}/lib \
              --with-version-build=${build} \
              --with-version-opt=aos \
              --with-version-pre= \
              --with-extra-cflags="-Wno-error -fcommon" \
              --with-extra-cxxflags="-Wno-error" \
              --with-extra-ldflags="''${NIX_LDFLAGS:-}" \
              --with-jobs=$NIX_BUILD_CORES
          '';
      }
      {
        name = "build";
        script = ''
          # Remove -z defs from generated spec.gmk — our xorg-stubs don't
          # export all X11 symbols and some JDK libs use runtime-resolved deps
          find build -name 'spec.gmk' 2>/dev/null | while read f; do
            sed -i 's/-Xlinker -z -Xlinker defs//g; s/-Wl,-z,defs//g' "$f" 2>/dev/null || true
          done

          make images JOBS=$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if isDarwinCross
          then ''
            mkdir -p $out
            cp -a build/*/images/jdk/* $out/
            test -x "$out/bin/java"
            test -x "$out/bin/javac"
            test -f "$out/lib/server/libjvm.dylib"
            test ! -e "$out/lib/libosxui.dylib"
            test ! -e "$out/lib/shaders.metallib"
          ''
          else ''
            mkdir -p $out
            cp -a build/*/images/jdk/* $out/

            # Patch ELF binaries with the correct dynamic linker and rpath
            INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
            BT_LIB=$(dirname "$INTERP")

            # Find libstdc++ directory (nested under lib/gcc/...)
            STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
            STDCXX_DIR=""
            if [ -n "$STDCXX_FILE" ]; then
              STDCXX_DIR=$(dirname "$STDCXX_FILE")
            fi
            RPATH="$out/lib:$out/lib/jli:$out/lib/server:$BT_LIB"
            if [ -n "$STDCXX_DIR" ]; then
              RPATH="$RPATH:$STDCXX_DIR"
            fi
            # Add runtime dependency library paths
            RPATH="$RPATH:${zlib}/lib:${fontconfig}/lib:${freetype}/lib"

            # Patch executables
            for f in $out/bin/* $out/lib/jspawnhelper; do
              if [ -f "$f" ] && [ ! -L "$f" ]; then
                patchelf --set-interpreter "$INTERP" \
                         --set-rpath "$RPATH" \
                         "$f" 2>/dev/null || true
              fi
            done

            # Patch shared libraries
            find $out/lib -name '*.so' -o -name '*.so.*' | while read f; do
              if [ -f "$f" ] && [ ! -L "$f" ]; then
                patchelf --set-rpath "$RPATH" \
                         "$f" 2>/dev/null || true
              fi
            done
          '';
      }
    ];

    meta = {
      description = "OpenJDK 25 — Java Development Kit built from source";
      homepage = "https://openjdk.org";
      license = "GPL-2.0-with-classpath-exception";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkVMTest {
        name = "toolchain-openjdk-version";
        rootfsDeps = [self];
        testScript = ''
          OUTPUT=$(java -version 2>&1)
          case "$OUTPUT" in
            *"25.0"*) ;;
            *) echo "==> ERROR: unexpected java version: $OUTPUT" >&2; exit 1 ;;
          esac
          echo "==> openjdk version: PASS"
        '';
      };

      compile-run = testing.mkVMTest {
        name = "toolchain-openjdk-compile-run";
        rootfsDeps = [self];
        testScript = ''
          # Write a simple Java program
          mkdir -p /tmp/jtest
          cat > /tmp/jtest/Hello.java << 'JAVA'
          public class Hello {
              public static void main(String[] args) {
                  System.out.println("Hello from AOS OpenJDK!");
                  System.out.println("Java version: " + System.getProperty("java.version"));
              }
          }
          JAVA

          # Compile and run
          javac /tmp/jtest/Hello.java
          OUTPUT=$(java -cp /tmp/jtest Hello)
          case "$OUTPUT" in
            *"Hello from AOS OpenJDK"*)
              echo "==> openjdk compile-run: PASS"
              ;;
            *)
              echo "==> ERROR: unexpected output: $OUTPUT" >&2
              exit 1
              ;;
          esac
        '';
      };

      jar = testing.mkVMTest {
        name = "toolchain-openjdk-jar";
        rootfsDeps = [self];
        testScript = ''
          # Create a JAR file and run it
          mkdir -p /tmp/jartest
          cat > /tmp/jartest/Main.java << 'JAVA'
          public class Main {
              public static void main(String[] args) {
                  System.out.println("JAR execution works!");
              }
          }
          JAVA

          javac /tmp/jartest/Main.java
          cat > /tmp/jartest/MANIFEST.MF << 'MF'
          Main-Class: Main
          MF
          jar cfm /tmp/jartest/test.jar /tmp/jartest/MANIFEST.MF -C /tmp/jartest Main.class

          OUTPUT=$(java -jar /tmp/jartest/test.jar)
          case "$OUTPUT" in
            *"JAR execution works"*)
              echo "==> openjdk jar: PASS"
              ;;
            *)
              echo "==> ERROR: unexpected JAR output: $OUTPUT" >&2
              exit 1
              ;;
          esac
        '';
      };
    };
  }
