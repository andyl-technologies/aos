##! classpath-0_99 — GNU Classpath 0.99 Java standard library (built with ECJ)
{
  mkDerivation,
  fetchurl,
  gnumake,
  ecj-bootstrap,
  fastjar,
  jamvm-1_5,
  classpath-0_93,
  pkg-config,
  zip,
}:
let
  version = "0.99";
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

  buildDeps = [
    gnumake
    ecj-bootstrap
    fastjar
    jamvm-1_5
    classpath-0_93
    pkg-config
    zip
  ];
  runtimeDeps = [ ];

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
        export JAVA="${jamvm-1_5}/bin/jamvm"
        export JAVAC="${ecj-bootstrap}/bin/ecj"

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
          --with-ecj-jar=${ecj-bootstrap}/lib/ecj.jar \
          --with-jar=${fastjar}/bin/fastjar \
          --with-vm=${jamvm-1_5}/bin/jamvm
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
