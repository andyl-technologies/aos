##! JavaScript AST dependency for the source-built early Kotlin compiler.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2012-09-30";
  buildJdk = buildPackages.openjdk-8;
  seed = import ./_kotlin-bootstrap-2011.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  source = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "720a8f250b8278fb604c2e6fecc33f9f16481dcb";
    name = "kotlin-dart-ast-java-source-only";
    hash = "sha256-k5yjdz3rlyZ8h2ic89qgtNuySEvivVM6b7aJIwHfLq8=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/src/"
      "/License.txt"
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
    pname = "kotlin-dart-ast-bootstrap";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.findutils
      buildPackages.coreutils
      seed
    ];
    runtimeDeps = [buildJdk seed];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source

          python3 - <<'PY'
          from pathlib import Path

          root = Path("source")
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("feedface"),
              bytes.fromhex("feedfacf"), bytes.fromhex("4d5a"),
          )
          for path in root.rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix not in {".java", ".txt"}:
                  raise SystemExit(f"Unexpected Dart AST input: {path}")
              if path.read_bytes().startswith(compiled_signatures):
                  raise SystemExit(f"Compiled Dart AST input: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          seedRoot=${seed}/share/kotlin-bootstrap
          classpath="$seedRoot/dist/classes/runtime:$seedRoot/deps/trove"

          find source/src -name '*.java' | LC_ALL=C sort > java-files
          mkdir -p classes
          ${buildJdk}/bin/javac -encoding UTF-8 -proc:none \
            -cp "$classpath" -d classes @java-files
        '';
      }
      {
        name = "check";
        script = ''
          cat > DartAstCheck.java <<'JAVA'
          import com.google.dart.compiler.backend.js.JsToStringGenerationVisitor;
          import com.google.dart.compiler.backend.js.ast.JsProgram;

          public final class DartAstCheck {
              public static void main(String[] args) {
                  JsProgram program = new JsProgram("aos");
                  if (program.getFragmentBlock(0) == null) {
                      throw new AssertionError("Dart AST did not create a program block");
                  }

                  String escaped = JsToStringGenerationVisitor.javaScriptString("AOS\n").toString();
                  if (!"'AOS\\n'".equals(escaped)) {
                      throw new AssertionError("Unexpected JavaScript string: " + escaped);
                  }
              }
          }
          JAVA

          ${buildJdk}/bin/javac -proc:none -cp "classes:$classpath" \
            -d classes DartAstCheck.java
          ${buildJdk}/bin/java -cp "classes:$classpath" DartAstCheck
          rm classes/DartAstCheck.class
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/kotlin-dart-ast" "$out/share/licenses/kotlin-dart-ast"
          cp -R classes "$out/share/kotlin-dart-ast/"
          cp source/License.txt "$out/share/licenses/kotlin-dart-ast/"
        '';
      }
    ];

    meta = {
      description = "Dart JavaScript AST compiled from source for Kotlin bootstrap";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "bsd3";
    };
  }
