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
      "https://ftp.gnu.org/gnu/classpath/classpath-${version}.tar.gz"
    ];
    hash = "sha256-+Skpf4rpthOhoWfiMVZoYYkyYGUdkTrZtsEZM4lf7Mg=";
  };

  buildDeps = [gnumake ecj-bootstrap fastjar jamvm-1_5 classpath-0_93 pkg-config zip];
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
      name = "configure";
      script = ''
        # ECJ needs a working JVM to run — set up the environment
        export JAVA="${jamvm-1_5}/bin/jamvm"
        export JAVAC="${ecj-bootstrap}/bin/ecj"
        export BOOTCLASSPATH="${classpath-0_93}/share/classpath/glibj.zip"

        ./configure \
          --prefix=$out \
          --disable-gtk-peer \
          --disable-gconf-peer \
          --disable-alsa \
          --disable-dssi \
          --disable-gjdoc \
          --disable-plugin \
          --disable-examples \
          --with-ecj-jar=${ecj-bootstrap}/lib/ecj.jar \
          --with-jar=${fastjar}/bin/fastjar \
          --with-vm=${jamvm-1_5}/bin/jamvm \
          --with-bootclasspath=${classpath-0_93}/share/classpath/glibj.zip
      '';
    }
    {
      name = "build";
      script = ''
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
