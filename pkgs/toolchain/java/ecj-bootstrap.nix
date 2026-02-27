##! ecj-bootstrap — Eclipse Compiler for Java 3.2.2 compiled with Jikes
{
  mkDerivation,
  fetchurl,
  jikes,
  fastjar,
  jamvm-1_5,
  classpath-0_93,
  unzip,
}:
let
  version = "3.2.2";
in
mkDerivation {
  pname = "ecj-bootstrap";
  inherit version;

  src = fetchurl {
    urls = [
      "https://archive.eclipse.org/eclipse/downloads/drops/R-3.2.2-200702121330/ecjsrc.zip"
    ];
    hash = "sha256-BwzUJfUyQ0kHPI6po6DUMWZCkmRYTanpU3iI1qdAEhY=";
  };

  buildDeps = [
    jikes
    fastjar
    jamvm-1_5
    classpath-0_93
    unzip
  ];
  runtimeDeps = [
    jamvm-1_5
    classpath-0_93
  ];

  phases = [
    {
      name = "unpack";
      script = ''
        mkdir -p ecjsrc
        cd ecjsrc
        unzip $src
      '';
    }
    {
      name = "build";
      script = ''
        # Find all Java source files
        find . -name '*.java' > sources.txt

        # Compile with Jikes against GNU Classpath
        # Jikes needs the bootclasspath to find core Java classes
        mkdir -p classes
        jikes -bootclasspath ${classpath-0_93}/share/classpath/glibj.zip \
          -d classes \
          -nowarn \
          @sources.txt

        # Package into ecj.jar
        cd classes
        ${fastjar}/bin/fastjar cf ../ecj.jar .
        cd ..
      '';
    }
    {
      name = "install";
      script = ''
                mkdir -p $out/lib $out/bin

                cp ecj.jar $out/lib/ecj.jar

                # Create wrapper script to invoke ECJ via JamVM
                cat > $out/bin/ecj <<WRAPPER
        #!/bin/sh
        exec ${jamvm-1_5}/bin/jamvm \
          -Xbootclasspath/p:${classpath-0_93}/share/classpath/glibj.zip \
          -jar $out/lib/ecj.jar "\$@"
        WRAPPER
                chmod +x $out/bin/ecj
      '';
    }
  ];

  meta = {
    description = "Eclipse Compiler for Java 3.2.2 — bootstrapped with Jikes";
    homepage = "https://www.eclipse.org/jdt/core/";
    license = "EPL-1.0";
  };
}
