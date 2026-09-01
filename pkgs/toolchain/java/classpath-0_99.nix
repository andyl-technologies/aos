##! classpath-0_99 — GNU Classpath 0.99 Java standard library (built with ECJ)
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  gnumake,
  ecj-bootstrap,
  fastjar,
  jamvm-1_5,
  classpath-0_93,
  pkg-config,
  zip,
}: let
  version = "0.99";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  configurePlatformFlags = lib.optionalString isDarwinCross " \\\n            --build=${stdenv.buildPlatform.config} \\\n            --host=${stdenv.hostPlatform.config}";
  ecjForBuild =
    if stdenv.isCross
    then buildPackages.ecj-bootstrap
    else ecj-bootstrap;
  fastjarForBuild =
    if stdenv.isCross
    then buildPackages.fastjar
    else fastjar;
  jamvmForBuild =
    if stdenv.isCross
    then buildPackages.jamvm-1_5
    else jamvm-1_5;
in
  mkDerivation {
    pname = "classpath-0_99";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/classpath/classpath-${version}.tar.gz"
      ];
      hash = "sha256-+Skpf4rpthOhoWfiMVZoYYkyYGUdkTrZtsEZM4lf7Mg=";
    };

    buildDeps =
      [
        gnumake
        ecjForBuild
        fastjarForBuild
        jamvmForBuild
        classpath-0_93
        pkg-config
        zip
      ]
      ++ lib.optionals isDarwinCross [buildPackages.automake];
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

          # Remove any stray 'sun' file in lib/ that blocks sun/ directory creation
          test -f lib/sun && rm lib/sun || true

          ${lib.optionalString isDarwinCross ''
            # This release predates AArch64. Refresh only the canonical target
            # table; its generated configure logic is otherwise cross-aware.
            cp ${buildPackages.automake}/share/automake-*/config.sub config.sub

            # GNU Classpath's fdlibm predates AArch64 but uses the standard
            # little-endian IEEE-754 word layout on that architecture.
            sed -i '/#ifdef __alpha__/i #ifdef __aarch64__\n#define __IEEE_LITTLE_ENDIAN\n#endif\n' \
              native/fdlibm/ieeefp.h

            # IUCLC is a Linux terminal extension. On Darwin the remaining
            # standard input flags still implement the intended echo guard.
            sed -i '/#define TERMIOS_ECHO_IFLAGS/i #ifndef IUCLC\n#define IUCLC 0\n#endif\n' \
              native/jni/java-io/java_io_VMConsole.c
          ''}

          # Fix: --disable-tools leaves GCJ_JAVAC automake conditional undefined
          # Insert default values just before the check that errors out
          sed -i 's/if test -z "''${GCJ_JAVAC_TRUE}" && test -z "''${GCJ_JAVAC_FALSE}"/GCJ_JAVAC_TRUE="''${GCJ_JAVAC_TRUE:-#}"; GCJ_JAVAC_FALSE="''${GCJ_JAVAC_FALSE:-}"; if test -z "''${GCJ_JAVAC_TRUE}" \&\& test -z "''${GCJ_JAVAC_FALSE}"/' configure
        '';
      }
      {
        name = "configure";
        script = ''
          # ECJ needs a working JVM to run — set up the environment
          # Do NOT set BOOTCLASSPATH env var — JamVM uses it to override its
          # boot classpath, and without classes.zip it fails to initialize.
          export JAVA="${jamvmForBuild}/bin/jamvm"
          export JAVAC="${ecjForBuild}/bin/ecj"

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
            --disable-tools \
            --with-ecj-jar=${ecjForBuild}/lib/ecj.jar \
            --with-jar=${fastjarForBuild}/bin/fastjar \
            --with-vm=${jamvmForBuild}/bin/jamvm${configurePlatformFlags}
        '';
      }
      {
        name = "build";
        script = ''
          # Pre-create the FULL package directory tree in lib/ before ECJ runs.
          # JamVM + classpath-0.93's File.mkdirs() has a bug where it creates
          # intermediate paths as empty files instead of directories, which
          # blocks subsequent class file output.
          # We must create ALL directories that ECJ will write to, by scanning
          # every .java source file and mirroring its package directory.
          (cd lib
           # Create dirs from all source trees
           for srcdir in .. ../external/w3c_dom ../external/sax ../external/relaxngDatatype ../external/jsr166; do
             if [ -d "$srcdir" ]; then
               find "$srcdir" -name '*.java' -print | while read f; do
                 d=$(dirname "$f" | sed "s|^$srcdir/||")
                 if [ -n "$d" ] && [ "$d" != "." ]; then
                   mkdir -p "$d"
                 fi
               done
             fi
           done
           # Also create META-INF
           mkdir -p META-INF
          )

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
      description = "GNU Classpath 0.99 — Java standard library built with ECJ";
      homepage = "https://www.gnu.org/software/classpath/";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
