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

    buildDeps = [buildJdk protobuf];
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

          find java/core/src/main/java generated -name '*.java' \
            ! -name module-info.java -print > java-sources
          javac --release 17 -proc:none -encoding UTF-8 \
            -d classes @java-sources
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
