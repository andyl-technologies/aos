##! ecj-bootstrap — Eclipse Compiler for Java 3.2.2 compiled with Jikes
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  jikes,
  fastjar,
  jamvm-1_5,
  classpath-0_93,
  ant-bootstrap,
  unzip,
}: let
  version = "3.2.2";
  jikesForBuild =
    if stdenv.isCross
    then buildPackages.jikes
    else jikes;
  fastjarForBuild =
    if stdenv.isCross
    then buildPackages.fastjar
    else fastjar;
  antBootstrapForBuild =
    if stdenv.isCross
    then buildPackages.ant-bootstrap
    else ant-bootstrap;
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
      jikesForBuild
      fastjarForBuild
      jamvm-1_5
      classpath-0_93
      antBootstrapForBuild
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
          # ECJ's JDTCompilerAdapter extends Ant's DefaultCompilerAdapter
          mkdir -p classes
          ${jikesForBuild}/bin/jikes -bootclasspath ${classpath-0_93}/share/classpath/glibj.zip \
            -classpath ${antBootstrapForBuild}/lib/ant.jar \
            -d classes \
            -nowarn \
            @sources.txt

          # Copy resource files (properties, etc.) into classes dir
          find . -maxdepth 1 -name '*.java' -prune -o -type f -name '*.properties' -print \
            -o -type f -name '*.rsc' -print \
            -o -type f -name '*.profile' -print | while read f; do
            dir=$(dirname "$f")
            mkdir -p "classes/$dir"
            cp "$f" "classes/$f"
          done

          # Also copy from org/eclipse subdirs
          find org -type f ! -name '*.java' | while read f; do
            dir=$(dirname "$f")
            mkdir -p "classes/$dir"
            cp "$f" "classes/$f"
          done

          # Package into ecj.jar
          cd classes
          ${fastjarForBuild}/bin/fastjar cf ../ecj.jar .
          cd ..
        '';
      }
      {
        name = "install";
        script = ''
                  mkdir -p $out/lib $out/bin

                  cp ecj.jar $out/lib/ecj.jar

          # Create wrapper script to invoke ECJ via JamVM
          # JamVM already has correct boot classpath from --with-classpath-install-dir
          # -J flags from callers are silently ignored (we set -Xmx768M directly)
          printf '#!/bin/sh\nexec %s -Xmx768M -cp %s org.eclipse.jdt.internal.compiler.batch.Main "$@"\n' \
            "${jamvm-1_5}/bin/jamvm" \
            "$out/lib/ecj.jar" \
            > $out/bin/ecj
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
