##! ecj-bootstrap — Eclipse Compiler for Java 3.2.2 compiled with Jikes
{
  lib,
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
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "ECJ writes Answer.class with the JVM CAFEBABE magic value.";
        "files" = {
          "Answer.java" = "public final class Answer {\n    public static int value() { return 42; }\n}\n";
        };
        "input" = "A Java class whose method returns the integer 42.";
        "operation" = "Compile the class and inspect the emitted JVM class-file header.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/ecj\", \"-source\", \"1.5\", \"-target\", \"1.5\", \"Answer.java\"], capture_output=True)\nassert result.returncode == 0, result.stderr\nassert pathlib.Path(\"Answer.class\").read_bytes()[:4] == b\"\\xca\\xfe\\xba\\xbe\"\nprint(\"ecj-bootstrap operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "ecj-bootstrap operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "ECJ emits a compiler diagnostic and rejects the source.";
        "files" = {
          "Broken.java" = "public class Broken { int value() { return ; } }\n";
        };
        "input" = "A Java class with a missing expression after return.";
        "operation" = "Compile the syntactically invalid class.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/ecj\", \"-source\", \"1.5\", \"-target\", \"1.5\", \"Broken.java\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nassert b\"ERROR\" in result.stdout + result.stderr\nsys.stderr.write(\"ecj-bootstrap rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "ecj-bootstrap rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
