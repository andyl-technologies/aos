##! August 2013 Kotlin standard library built with the source-built compiler.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2013-08-30";
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
  compiler = import ./_kotlin-bootstrap-serialized-2013.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  source = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "440716c81713a3a14cace55e335d7bddec2c5e06";
    name = "kotlin-2013-stdlib-source-only";
    hash = "sha256-Yr1ED97pRKiBEaKX9aTflxprVVryiq1gKH6LFDnPwyo=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/libraries/stdlib/src/"
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

          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".bin", ".class", ".dll", ".dylib", ".exe", ".jar", ".so", ".wasm",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("feedface"),
              bytes.fromhex("feedfacf"), bytes.fromhex("4d5a"),
          )
          for path in Path("kotlin").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled Kotlin input: {path}")
              if path.read_bytes().startswith(compiled_signatures):
                  raise SystemExit(f"Compiled Kotlin input: {path}")
          PY

          test -s kotlin/jdk-annotations/java/util/annotations.xml
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

          mkdir -p classes/parser classes/stdlib
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -d classes/parser ${./kotlin-bootstrap}/SAXParser.java

          classpath="classes/parser:$compilerRoot/kotlin:$coreRoot/classes:$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:$protobufRoot/classes:$compilerRoot/seed"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done

          # The 2013 class reader needs JDK 7 bytecode. The compiler itself
          # runs on JDK 8 because one earlier bootstrap tool targets Java 8.
          if ! java -cp "$classpath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk -noJdkAnnotations \
            -classpath "${classpathJdk}/jre/lib/rt.jar:$compilerRoot/kotlin" \
            -annotations "$PWD/kotlin/jdk-annotations" \
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
          test "$(find classes/stdlib -name '*.class' | wc -l)" -ge 200

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
          javac -proc:none -cp "classes/stdlib:$compilerRoot/kotlin" \
            -d classes/check StdlibCheck.java
          java -cp "classes/check:classes/stdlib:$compilerRoot/kotlin" StdlibCheck
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
      description = "August 2013 Kotlin standard library compiled from Kotlin sources";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "Apache-2.0";
    };
  }
