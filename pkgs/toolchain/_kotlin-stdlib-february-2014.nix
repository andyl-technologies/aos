##! February 2014 Kotlin standard library built with the December compiler.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2014-02-28";
  buildJdk = buildPackages.openjdk-8;
  classpathJdk = buildPackages.openjdk-7;
  seed = import ./_kotlin-bootstrap-2011.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  marchStage = import ./_kotlin-bootstrap-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  juneStage = import ./_kotlin-bootstrap-june-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  octoberApi = import ./_kotlin-idea-api-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  ideaCore = import ./_kotlin-idea-core-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  protobufLite = import ./_protobuf-java-lite-2_5.nix {
    inherit mkDerivation fetchurl buildPackages;
  };
  compiler = import ./_kotlin-bootstrap-december-2013.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  jdkAnnotations = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "7cf587c49375d70864360d9de0fbf7873109212f";
    name = "kotlin-2014-january-jdk-annotations-source-only";
    hash = "sha256-GTYjOnSwaG/w71vHuSOpC9FaPRVj/O5pmzJ5ue3LaEM=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/jdk-annotations/"
      "!*.jar"
      "!*.class"
      "!*.so"
      "!*.dylib"
      "!*.dll"
      "!*.exe"
      "!*.bin"
      "!*.wasm"
      "!*.zip"
      "!*.gz"
    ];
  };

  source = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "9efdd136ba075b7aa27d3f72587180ca5688cba3";
    name = "kotlin-2014-february-stdlib-source-only";
    hash = "sha256-cyhDYPjZ7UJ1E6RuqRhQM4jUP63oAf7H04oXHMUGnUA=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/libraries/stdlib/src/"
      "!*.jar"
      "!*.class"
      "!*.so"
      "!*.dylib"
      "!*.dll"
      "!*.exe"
      "!*.bin"
      "!*.wasm"
      "!*.zip"
      "!*.gz"
      "!*.kotlin_class"
      "!*.kotlin_name_table"
      "!*.kotlin_class_names"
      "!*.kotlin_package"
    ];
  };
in
  mkDerivation {
    pname = "kotlin-stdlib-bootstrap";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      classpathJdk
      buildPackages.python3
      buildPackages.findutils
      buildPackages.coreutils
      seed
      marchStage
      juneStage
      octoberApi
      ideaCore
      protobufLite
      compiler
    ];
    runtimeDeps = [buildJdk compiler];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" kotlin
          cp -R ${jdkAnnotations}/jdk-annotations jdk-annotations
          chmod -R u+w jdk-annotations
          cp -R ${./kotlin-february-annotations}/. jdk-annotations/

          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".bin", ".class", ".dll", ".dylib", ".exe", ".jar", ".so", ".wasm",
              ".kotlin_class", ".kotlin_name_table", ".kotlin_class_names", ".kotlin_package",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("feedface"),
              bytes.fromhex("feedfacf"), bytes.fromhex("4d5a"),
          )
          for root in (Path("kotlin"), Path("jdk-annotations")):
              for path in root.rglob("*"):
                  if not path.is_file():
                      continue
                  if path.suffix.lower() in compiled_suffixes or path.name.startswith(".kotlin_"):
                      raise SystemExit(f"Compiled Kotlin input: {path}")
                  if path.read_bytes().startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Kotlin input: {path}")
          PY

        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH=${buildJdk}/bin:$PATH
          seedRoot=${seed}/share/kotlin-bootstrap
          marchRoot=${marchStage}/share/kotlin-bootstrap
          juneRoot=${juneStage}/share/kotlin-bootstrap
          apiRoot=${octoberApi}/share/kotlin-idea-api
          coreRoot=${ideaCore}/share/kotlin-idea-core
          protobufRoot=${protobufLite}/share/protobuf-java-lite
          compilerRoot=${compiler}/share/kotlin-bootstrap

          mkdir -p classes/stdlib

          classpath="$compilerRoot/parser:$compilerRoot/metadata:$compilerRoot/cli:$compilerRoot/core:$compilerRoot/plugin:$compilerRoot/light:$compilerRoot/storage:$coreRoot/classes:$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:$protobufRoot/classes:$seedRoot/dist/classes/runtime"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done

          # The December reader needs JDK 7 bytecode and source-generated
          # builtins metadata. The compiler itself runs on JDK 8.
          if ! java -cp "$classpath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk \
            -classpath "${classpathJdk}/jre/lib/rt.jar:$compilerRoot/core" \
            -annotations "$PWD/jdk-annotations" \
            -src "$PWD/kotlin/libraries/stdlib/src" \
            -output "$PWD/classes/stdlib" > stdlib.log 2>&1; then
            tail -60 stdlib.log
            exit 1
          fi
        '';
      }
      {
        name = "check";
        script = ''
          test "$(find classes/stdlib -name '*.class' | wc -l)" -ge 220
          test -s classes/stdlib/kotlin/properties/Delegates.class
          test -s classes/stdlib/kotlin/modules/Module.class

          cat > StdlibCheck.java <<'JAVA'
          import java.util.ArrayList;
          import java.util.Arrays;
          import kotlin.KotlinPackage;

          public final class StdlibCheck {
              public static void main(String[] args) {
                  ArrayList<String> values = KotlinPackage.toArrayList(
                      Arrays.asList("first", "second").iterator());
                  if (values.size() != 2 || !"second".equals(values.get(1))) {
                      throw new AssertionError("Kotlin standard library lost collection values");
                  }
              }
          }
          JAVA

          mkdir -p classes/check
          javac -proc:none -cp "classes/stdlib:$compilerRoot/core:$compilerRoot/storage" \
            -d classes/check StdlibCheck.java
          java -cp "classes/check:classes/stdlib:$compilerRoot/core:$compilerRoot/storage" StdlibCheck
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/kotlin-stdlib"
          cp -R classes/stdlib "$out/share/kotlin-stdlib/classes"
        '';
      }
    ];

    meta = {
      description = "February 2014 Kotlin standard library compiled from Kotlin sources";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "Apache-2.0";
    };
  }
