##! Source-built Google common protos 2.41.0 for Bazel's Maven graph.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelProtobufJava,
}: let
  version = "2.41.0";
  buildJdk = buildPackages.openjdk-17;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/google/api/grpc/proto-google-common-protos/${version}/proto-google-common-protos-${version}-sources.jar"];
    hash = "sha256-qALc8qPzK5OyfjuFmI2wjeg0zdMtKia18aHwTKT6vKs=";
  };

  library = mkDerivation {
    pname = "bazel-common-protos";
    inherit version;
    src = source;

    buildDeps = [buildJdk bazelProtobufJava buildPackages.findutils buildPackages.python3 buildPackages.unzip];
    runtimeDeps = [bazelProtobufJava];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - ${source} <<'PY'
          import sys
          from zipfile import ZipFile

          compiled_suffixes = (
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          )
          with ZipFile(sys.argv[1]) as archive:
              for member in archive.infolist():
                  if member.is_dir():
                      continue
                  if member.filename.lower().endswith(compiled_suffixes):
                      raise SystemExit(f"Compiled payload in common protos source: {member.filename}")
                  if b"\0" in archive.read(member):
                      raise SystemExit(f"Opaque payload in common protos source: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p source classes
          unzip -q ${source} -d source
          find source/com -name '*.java' -print > java-sources
          javac --release 17 -proc:none -encoding UTF-8 \
            -cp ${bazelProtobufJava}/share/java/protobuf-java-${bazelProtobufJava.version}.jar \
            -d classes @java-sources

          find source -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              relative=''${resource#source/}
              destination="classes/$relative"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done
        '';
      }
      {
        name = "check";
        script = ''
          cat > CommonProtosCheck.java <<'JAVA'
          import com.google.rpc.Status;

          public final class CommonProtosCheck {
              public static void main(String[] args) {
                  if (!Status.getDescriptor().getFullName().equals("google.rpc.Status")) {
                      throw new AssertionError("Common protos descriptor is unavailable");
                  }
              }
          }
          JAVA

          javac --release 17 -cp "classes:${bazelProtobufJava}/share/java/protobuf-java-${bazelProtobufJava.version}.jar" \
            CommonProtosCheck.java
          java -cp "classes:.:${bazelProtobufJava}/share/java/protobuf-java-${bazelProtobufJava.version}.jar" \
            CommonProtosCheck
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          jar --create --file "$out/share/java/proto-google-common-protos-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  };

  repository = mkDerivation {
    pname = "bazel-maven-common-protos-source";
    inherit version;
    src = library;

    buildDeps = [];
    runtimeDeps = [library];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/file"
          printf 'workspace(name = "bazel_maven_common_protos")\n' > "$out/WORKSPACE"
          cp ${library}/share/java/proto-google-common-protos-${version}.jar \
            "$out/file/artifact.jar"
          cat > "$out/file/BUILD.bazel" <<'BUILD'
          package(default_visibility = ["//visibility:public"])
          filegroup(name = "file", srcs = ["artifact.jar"])
          BUILD
        '';
      }
    ];
  };

  emptyListenableFuture = mkDerivation {
    pname = "bazel-maven-empty-listenablefuture";
    version = "9999.0-empty-to-avoid-conflict-with-guava";
    src = null;

    buildDeps = [buildJdk];
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p "$out/file" empty
          printf 'workspace(name = "bazel_maven_empty_listenablefuture")\n' > "$out/WORKSPACE"
          jar --create --file "$out/file/artifact.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C empty .
          cat > "$out/file/BUILD.bazel" <<'BUILD'
          package(default_visibility = ["//visibility:public"])
          filegroup(name = "file", srcs = ["artifact.jar"])
          BUILD
        '';
      }
    ];
  };
in {
  inherit library repository emptyListenableFuture;
}
