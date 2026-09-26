##! Source-built Protobuf Java runtime for Bazel's source bootstrap.
{
  mkDerivation,
  buildPackages,
  protobuf,
}: let
  version = "36.1";
  buildJdk = buildPackages.openjdk-17;
in
  mkDerivation {
    pname = "bazel-protobuf-java";
    inherit version;
    src = protobuf.src;

    buildDeps = [buildJdk protobuf buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd protobuf-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p generated classes
          for proto in any api descriptor duration empty field_mask \
            source_context struct timestamp type wrappers; do
            echo "src/google/protobuf/$proto.proto"
          done > well-known-protos
          printf '%s\n' \
            java/core/src/main/resources/google/protobuf/java_features.proto \
            java/core/src/main/resources/google/protobuf/java_mutable_features.proto \
            >> well-known-protos
          protoc -I src -I java/core/src/main/resources \
            --java_out=generated $(cat well-known-protos)

          # The enum switch initializes a compiler-generated mapping class that
          # also touches WireFormat while Internal's empty stream is starting.
          # Equivalent comparisons keep the varint selection and break the cycle.
          python3 - <<'PY'
          from pathlib import Path

          source = Path("java/core/src/main/java/com/google/protobuf/CodedInputStream.java")
          original = """    switch (varintExperiment) {
                case NEW_ALL_CASES:
                  result = new ArrayDecoderNewVarintAllCases(buf, off, len, bufferIsImmutable);
                  break;
                case NEW_TAGS_LENGTHS_UNSIGNED_ONLY:
                  result = new ArrayDecoderNewVarintTagsLengthsOnly(buf, off, len, bufferIsImmutable);
                  break;
                case CONTROL:
                default:
                  result = new ArrayDecoderOldVarint(buf, off, len, bufferIsImmutable);
                  break;
              }"""
          replacement = """    if (varintExperiment == VarintExperiment.NEW_ALL_CASES) {
                result = new ArrayDecoderNewVarintAllCases(buf, off, len, bufferIsImmutable);
              } else if (varintExperiment == VarintExperiment.NEW_TAGS_LENGTHS_UNSIGNED_ONLY) {
                result = new ArrayDecoderNewVarintTagsLengthsOnly(buf, off, len, bufferIsImmutable);
              } else {
                result = new ArrayDecoderOldVarint(buf, off, len, bufferIsImmutable);
              }"""

          contents = source.read_text()
          if contents.count(original) != 1:
              raise SystemExit("Unexpected Protobuf CodedInputStream varint selector")
          source.write_text(contents.replace(original, replacement))
          PY

          find java/core/src/main/java generated -name '*.java' \
            ! -name module-info.java -print > java-sources
          javac --release 17 -proc:none -encoding UTF-8 \
            -d classes @java-sources
        '';
      }
      {
        name = "check";
        script = ''
          cat > ProtobufBootstrapCheck.java <<'JAVA'
          import com.google.protobuf.CodedInputStream;
          import com.google.protobuf.DescriptorProtos;

          public final class ProtobufBootstrapCheck {
              public static void main(String[] args) throws Exception {
                  if (!CodedInputStream.newInstance(new byte[0]).isAtEnd()) {
                      throw new AssertionError("Empty input stream is not at end");
                  }
                  if (!DescriptorProtos.getDescriptor().getFullName()
                          .equals("google/protobuf/descriptor.proto")) {
                      throw new AssertionError("Descriptor initialization failed");
                  }
              }
          }
          JAVA

          javac --release 17 -cp classes ProtobufBootstrapCheck.java
          java -cp classes:. ProtobufBootstrapCheck
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p jar-resources/google/protobuf
          while IFS= read -r proto; do
            cp "$proto" "jar-resources/google/protobuf/$(basename "$proto")"
          done < well-known-protos

          mkdir -p "$out/share/java" "$out/share/licenses/protobuf"
          jar --create --file "$out/share/java/protobuf-java-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z \
            -C classes . -C jar-resources .
          cp LICENSE "$out/share/licenses/protobuf/LICENSE"
        '';
      }
    ];
  }
