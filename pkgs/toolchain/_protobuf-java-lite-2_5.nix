##! Protobuf 2.5 Lite Java runtime for the historical Kotlin compiler bootstrap.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "2.5.0";
  buildJdk = buildPackages.openjdk-8;
in
  mkDerivation {
    pname = "protobuf-java-lite-bootstrap";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/protocolbuffers/protobuf/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-wmZaeqKsGiBuYbKOAUSG495ZAJ6ivivekYLghH84ti8=";
    };

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd protobuf-${version}

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
          for path in Path(".").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled Protobuf input: {path}")
              if path.read_bytes().startswith(compiled_signatures):
                  raise SystemExit(f"Compiled Protobuf input: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes
          sourceRoot=java/src/main/java
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -sourcepath "$sourceRoot" -d classes \
            "$sourceRoot/com/google/protobuf/GeneratedMessageLite.java" \
            "$sourceRoot/com/google/protobuf/LazyStringArrayList.java" \
            "$sourceRoot/com/google/protobuf/UnmodifiableLazyStringList.java"
        '';
      }
      {
        name = "check";
        script = ''
          cat > ProtobufLiteCheck.java <<'JAVA'
          import com.google.protobuf.CodedInputStream;
          import com.google.protobuf.CodedOutputStream;
          import java.io.ByteArrayOutputStream;

          public final class ProtobufLiteCheck {
              public static void main(String[] args) throws Exception {
                  ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                  CodedOutputStream output = CodedOutputStream.newInstance(bytes);
                  output.writeInt32NoTag(42);
                  output.flush();

                  CodedInputStream input = CodedInputStream.newInstance(bytes.toByteArray());
                  if (input.readInt32() != 42 || !input.isAtEnd()) {
                      throw new AssertionError("Protobuf Lite round trip failed");
                  }
              }
          }
          JAVA

          javac -proc:none -cp classes -d classes ProtobufLiteCheck.java
          java -cp classes ProtobufLiteCheck
          rm classes/ProtobufLiteCheck.class
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/protobuf-java-lite" "$out/share/licenses/protobuf"
          cp -R classes "$out/share/protobuf-java-lite/classes"
          cp COPYING.txt "$out/share/licenses/protobuf/COPYING.txt"
        '';
      }
    ];

    meta = {
      description = "Protobuf 2.5 Lite Java runtime built from source";
      homepage = "https://github.com/protocolbuffers/protobuf";
      license = "BSD-3-Clause";
    };
  }
