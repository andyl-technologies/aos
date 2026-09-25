##! Source-built Protobuf Java utilities for Bazel's source bootstrap.
{
  mkDerivation,
  buildPackages,
  protobuf,
  protobufJava,
  bazelMavenBootstrap,
}: let
  version = "36.1";
  buildJdk = buildPackages.openjdk-17;
  protobufJar = "${protobufJava}/share/java/protobuf-java-${protobufJava.version}.jar";
  gsonJar = "${bazelMavenBootstrap}/maven/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar";
  errorProneAnnotationsJar = "${bazelMavenBootstrap}/maven/com/google/errorprone/error_prone_annotations/2.36.0/error_prone_annotations-2.36.0.jar";
  jsr305Jar = "${bazelMavenBootstrap}/maven/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar";
in
  mkDerivation {
    pname = "bazel-protobuf-java-util";
    inherit version;
    src = protobuf.src;

    buildDeps = [buildJdk protobuf protobufJava bazelMavenBootstrap];
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
          protoc -I src --java_out=generated \
            src/google/protobuf/json_enumvalue_options.proto
          find java/util/src/main/java generated -name '*.java' \
            ! -name module-info.java -print > java-sources
          javac --release 17 -proc:none -encoding UTF-8 \
            -cp "${protobufJar}:${gsonJar}:${errorProneAnnotationsJar}:${jsr305Jar}" \
            -d classes @java-sources
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java" "$out/share/licenses/protobuf"
          jar --create --file "$out/share/java/protobuf-java-util-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp LICENSE "$out/share/licenses/protobuf/LICENSE"
        '';
      }
    ];
  }
