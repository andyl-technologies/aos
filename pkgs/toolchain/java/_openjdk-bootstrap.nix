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
            # Configure the emitted JDK for Darwin while retaining a native
            # boot JDK. Darwin uses its CoreAudio port, so ALSA must not enter
            # either the target inputs or configure result.
            $CONFIG_SHELL configure \
              --openjdk-target=${stdenv.hostPlatform.config} \
              --with-boot-jdk=${bootJdk} \
              --enable-headless-only \
              --with-native-debug-symbols=none \
              --disable-warnings-as-errors \
              --with-zlib=system \
              --with-libjpeg=bundled \
              --with-giflib=bundled \
              --with-libpng=bundled \
              --with-lcms=bundled \
              --with-cups-include=${cups}/include \
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
