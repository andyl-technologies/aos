##! OpenJDK 21 — Java Development Kit built from source
{
  mkDerivation,
  fetchurl,
  lib,
  make,
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
  openjdk-bootstrap,
}:
let
  version = "21.0.10";
  build = "7";
  tag = "jdk-${version}+${build}";
in
mkDerivation {
  pname = "openjdk";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/openjdk/jdk21u/archive/refs/tags/${tag}.tar.gz"
    ];
    hash = "sha256-ZQCQbLfMSSaM5Mo2jbPd81QbQK/SXuyzeOE9WnL0MhQ=";
  };

  buildDeps = [
    make
    autoconf
    bash
    which
    zip
    unzip
    gawk
    coreutils
    binutils
    file
  ];
  runtimeDeps = [
    zlib
  ];
  propagatedDeps = [ ];

  patches = [
    ./openjdk-patches/fix-java-home-jdk21.patch
    ./openjdk-patches/read-truststore-from-env-jdk10.patch
    ./openjdk-patches/currency-date-range-jdk10.patch
    ./openjdk-patches/increase-javadoc-heap-jdk13.patch
    ./openjdk-patches/ignore-LegalNoticeFilePlugin-jdk18.patch
    ./openjdk-patches/gnumake-4.4.1.patch
  ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd jdk21u-*
      '';
    }
    {
      name = "configure";
      script = ''
        # OpenJDK configure requires bash
        $CONFIG_SHELL configure \
          --with-boot-jdk=${openjdk-bootstrap} \
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
          --with-version-build=${build} \
          --with-version-opt=aos \
          --with-version-pre= \
          --with-extra-cflags="-Wno-error" \
          --with-extra-ldflags="''${NIX_LDFLAGS:-}" \
          --with-jobs=$NIX_BUILD_CORES
      '';
    }
    {
      name = "build";
      script = ''
        make images JOBS=$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        cp -a build/*/images/jdk/* $out/

        # Patch ELF binaries with the correct dynamic linker and rpath
        INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
        BT_LIB=$(dirname "$INTERP")

        # Patch executables
        for f in $out/bin/* $out/lib/jspawnhelper; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" \
                     --set-rpath "$out/lib:$out/lib/server:$BT_LIB" \
                     "$f" 2>/dev/null || true
          fi
        done

        # Patch shared libraries
        find $out/lib -name '*.so' -o -name '*.so.*' | while read f; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-rpath "$out/lib:$out/lib/server:$BT_LIB" \
                     "$f" 2>/dev/null || true
          fi
        done
      '';
    }
  ];

  meta = {
    description = "OpenJDK 21 — Java Development Kit built from source";
    homepage = "https://openjdk.org";
    license = "GPL-2.0-with-classpath-exception";
  };

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkVMTest {
        name = "toolchain-openjdk-version";
        rootfsDeps = [ self ];
        testScript = ''
          OUTPUT=$(java -version 2>&1)
          case "$OUTPUT" in
            *"21.0"*) ;;
            *) echo "==> ERROR: unexpected java version: $OUTPUT" >&2; exit 1 ;;
          esac
          echo "==> openjdk version: PASS"
        '';
      };

      compile-run = testing.mkVMTest {
        name = "toolchain-openjdk-compile-run";
        rootfsDeps = [ self ];
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
        rootfsDeps = [ self ];
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
