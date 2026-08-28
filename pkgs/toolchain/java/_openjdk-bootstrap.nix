##! Shared builder for intermediate OpenJDK bootstrap compilers.
##! Underscore prefix = not auto-discovered. Imported by openjdk-N.nix files.
{
  stdenv,
  buildPackages,
  fetchurl,
  mkDerivation,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  gawk,
  coreutils,
  zlib,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  bootstrapTools,
}: {
  major,
  version,
  build,
  srcHash,
  prevJdk,
  repoSuffix ? "u",
  extraConfigureFlags ? [],
  extraBuildDeps ? [],
  extraPatches ? [],
  # Override build parallelism (defaults to $NIX_BUILD_CORES).
  # Useful when the boot JDK has javac concurrency bugs.
  buildJobs ? null,
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
    then builtins.getAttr "openjdk-${toString (major - 1)}" buildPackages
    else prevJdk;
  nativeMig =
    if isDarwinCross
    then
      import ./_darwin-mig.nix {
        inherit fetchurl buildPackages;
      }
    else null;
  tag = "jdk-${version}+${build}";
  repo = "jdk${toString major}${repoSuffix}";
  extraCfgStr = builtins.concatStringsSep " " extraConfigureFlags;
  jobsExpr =
    if buildJobs != null
    then toString buildJobs
    else "$NIX_BUILD_CORES";
in
  mkDerivation {
    pname = "openjdk-${toString major}";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/openjdk/${repo}/archive/refs/tags/${tag}.tar.gz"
      ];
      hash = srcHash;
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
      ++ (
        if isDarwinCross
        then [nativeMig buildTools.python3]
        else []
      )
      ++ extraBuildDeps;
    runtimeDeps = [
      zlib
      fontconfig
      freetype
    ];

    patches = extraPatches;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jdk*-*

          # GCC 14 makes "ordered comparison of pointer with integer zero" a hard
          # error in C++.  Fix the two occurrences in JDK 9 hotspot source.
          for f in hotspot/src/share/vm/opto/lcm.cpp src/hotspot/share/opto/lcm.cpp; do
            if [ -f "$f" ]; then
              sed -i 's/narrow_oop_base() > 0/narrow_oop_base() != (address)0/' "$f"
            fi
          done
          for f in hotspot/src/share/vm/memory/virtualspace.cpp src/hotspot/share/gc/shared/virtualspace.cpp; do
            if [ -f "$f" ]; then
              sed -i 's/base() > 0/base() != (char*)0/' "$f"
            fi
          done
          # Fix os_linux.cpp: "if (p < 0)" where p is char*
          for f in hotspot/src/os/linux/vm/os_linux.cpp src/hotspot/os/linux/os_linux.cpp; do
            if [ -f "$f" ]; then
              sed -i 's/if (p < 0)/if (p == NULL)/' "$f"
            fi
          done

          # Extend currency date range check from 10 to 20 years (builds break
          # when currency data entries exceed 10 years from build date).
          for f in \
            jdk/make/src/classes/build/tools/generatecurrencydata/GenerateCurrencyData.java \
            make/jdk/src/classes/build/tools/generatecurrencydata/GenerateCurrencyData.java; do
            if [ -f "$f" ]; then
              sed -i 's/((long) 10) \* 365/((long) 20) * 365/; s/more than 10 years/more than 20 years/' "$f"
            fi
          done

          # Fix DependOnVariable for GNU Make 4.3+ compatibility (JDK-8237879).
          # Replace $(eval -include ...) with $(if $(wildcard ...),$(eval include ...))
          # This was fixed upstream in JDK 11.0.8+ but never backported to JDK 9/10.
          if [ -f make/common/MakeBase.gmk ]; then
            sed -i 's/$(eval -include $(call DependOnVariableFileName, $1, $2))/$(if $(wildcard $(call DependOnVariableFileName, $1, $2)),$(eval include $(call DependOnVariableFileName, $1, $2)))/' make/common/MakeBase.gmk
          fi
        '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
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
            if [ -f make/common/native/CompileFile.gmk ]; then
              pchGmk=make/common/native/CompileFile.gmk
            else
              pchGmk=make/common/NativeCompilation.gmk
            fi
            sed -i \
              's/$1_PCH_COMMAND := $$($1_CC)/$1_PCH_COMMAND := $$($1_CXX)/' \
              "$pchGmk"
            grep -q '^        $1_PCH_COMMAND := $$($1_CXX)' "$pchGmk"

            # AOS deliberately builds the existing headless JDK variant. The
                        # macOS port otherwise probes Xcode's proprietary Metal tools and
                        # builds libosxui even when headless-only is enabled. Gate both
                        # together so this feature boundary is honored without fake tools.
                        toolchainM4=make/autoconf/toolchain.m4
                        clientLibraries=make/modules/java.desktop/lib/ClientLibraries.gmk
                        if [ -f "$toolchainM4" ] \
                          && grep -q '^    UTIL_LOOKUP_TOOLCHAIN_PROGS(METAL, metal)$' "$toolchainM4"; then
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
                        fi
                        if [ -f "$clientLibraries" ]; then
                          sed -i \
                            's/^ifeq ($(call isTargetOs, macosx), true)$/ifeq ($(call isTargetOs, macosx)+$(ENABLE_HEADLESS_ONLY), true+false)/' \
                            "$clientLibraries"
                          grep -q '^ifeq ($(call isTargetOs, macosx)+$(ENABLE_HEADLESS_ONLY), true+false)$' \
                            "$clientLibraries"
                        fi

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

                        # Configure the emitted JDK for Darwin while retaining a native
                        # boot JDK. Darwin uses its CoreAudio port, so ALSA must not enter
                        # either the target inputs or configure result.
                        $CONFIG_SHELL configure \
                          BUILD_CC=$darwinTools/build-clang \
                          BUILD_CXX=$darwinTools/build-clang++ \
                          --openjdk-target=${stdenv.hostPlatform.config} \
                          --with-toolchain-type=clang \
                          --with-boot-jdk=${bootJdk} \
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
                          --with-extra-cflags="-Wno-error -fcommon -fno-lifetime-dse -fno-delete-null-pointer-checks" \
                          --with-extra-cxxflags="-Wno-error -fno-lifetime-dse -fno-delete-null-pointer-checks" \
                          --with-extra-ldflags="$darwinLdflags" \
                          --with-jobs=${jobsExpr} \
                          ${extraCfgStr}
                        grep -q '^ENABLE_HEADLESS_ONLY := true$' build/*/spec.gmk
          ''
          else ''
            $CONFIG_SHELL configure \
              --with-boot-jdk=${prevJdk} \
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
              --with-extra-cflags="-Wno-error -fcommon -fno-lifetime-dse -fno-delete-null-pointer-checks" \
              --with-extra-cxxflags="-Wno-error -fno-lifetime-dse -fno-delete-null-pointer-checks" \
              --with-extra-ldflags="''${NIX_LDFLAGS:-}" \
              --with-jobs=${jobsExpr} \
              ${extraCfgStr}
          '';
      }
      {
        name = "build";
        script = ''
          # Disable AVX-512 in glibc to prevent SIGSEGV in memmove during JVM
          # bootstrap (older JDK hotspot code has alignment issues with AVX-512)
          export GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512F

          # Remove -z defs from generated spec.gmk — our xorg-stubs don't
          # export all X11 symbols and some JDK libs use runtime-resolved deps
          find build -name 'spec.gmk' 2>/dev/null | while read f; do
            sed -i 's/-Xlinker -z -Xlinker defs//g; s/-Wl,-z,defs//g' "$f" 2>/dev/null || true
          done

          make images JOBS=${jobsExpr}
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
      description = "OpenJDK ${toString major} — bootstrap chain intermediate";
      homepage = "https://openjdk.org";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
