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

    buildDeps = [
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
    ];
    runtimeDeps = [
      zlib
      fontconfig
      freetype
    ];
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
            # Build tools and the boot JDK execute on Linux, but the emitted
            # image is Darwin. OpenJDK selects CoreAudio for this target, so an
            # ALSA path would both misconfigure audio and pull Linux code into
            # the target closure.
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
              --with-extra-cflags="-Wno-error -fcommon" \
              --with-extra-cxxflags="-Wno-error" \
              --with-extra-ldflags="''${NIX_LDFLAGS:-}" \
              --with-jobs=$NIX_BUILD_CORES
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
