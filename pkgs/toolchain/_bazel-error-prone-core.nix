##! Error Prone Core compiled from its complete Java source archive.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelErrorProneCheckApi,
  bazelErrorProneDataflow,
  bazelGoogleJavaFormat,
  bazelProtobufJava,
}: let
  version = "2.36.0";
  buildJdk = buildPackages.openjdk-21;
  checkApiJar = "${bazelErrorProneCheckApi}/maven/com/google/errorprone/error_prone_check_api/${version}/error_prone_check_api-${version}.jar";
  dataflowVersion = bazelErrorProneDataflow.version;
  dataflowJar = "${bazelErrorProneDataflow}/maven/io/github/eisop/dataflow-errorprone/${dataflowVersion}/dataflow-errorprone-${dataflowVersion}.jar";
  formatVersion = bazelGoogleJavaFormat.version;
  formatJar = "${bazelGoogleJavaFormat}/maven/com/google/googlejavaformat/google-java-format/${formatVersion}/google-java-format-${formatVersion}.jar";
  protobufJar = "${bazelProtobufJava}/share/java/protobuf-java-${bazelProtobufJava.version}.jar";

  license = fetchurl {
    urls = ["https://raw.githubusercontent.com/google/error-prone/ab522c7dcac5e83b84828d5670595e5582d71fb3/COPYING"];
    hash = "sha256-z8d0m5b2O9McPEK1xHG/dWgUBT6EfBDz6wA0F7xSPTA=";
  };
in
  mkDerivation {
    pname = "bazel-error-prone-core";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_core/${version}/error_prone_core-${version}-sources.jar"];
      hash = "sha256-KSLKrx0hNIi1g4Qk2B0kCgGZVeeFm9mYVJYGaKayNxc=";
    };

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.protobuf
      buildPackages.findutils
      buildPackages.diffutils
      bazelMavenBootstrap
      bazelErrorProneCheckApi
      bazelErrorProneDataflow
      bazelGoogleJavaFormat
      bazelProtobufJava
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          python3 - "$src" <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe",
              "4d5a", "504b0304", "504b0506",
          ))

          with ZipFile(sys.argv[1]) as archive:
              for member in archive.infolist():
                  path = PurePosixPath(member.filename)
                  kind = stat.S_IFMT(member.external_attr >> 16)
                  if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                      raise SystemExit(f"Unsafe Error Prone Core source: {path}")
                  if member.is_dir():
                      continue

                  data = archive.read(member)
                  if path.suffix.lower() in compiled_suffixes or data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Error Prone Core source: {path}")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 960:
              raise SystemExit(f"Expected 960 Error Prone Core sources, found {len(sources)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          # The four API snapshots are schema-defined protobuf data. Decode
          # and re-encode each one to reject unknown or opaque payloads.
          resources=source/com/google/errorprone/bugpatterns/apidiff
          test "$(find "$resources" -name '*.binarypb' | wc -l)" -eq 4
          for resource in "$resources"/*.binarypb; do
            protoc -Isource \
              --decode=devtools.staticanalysis.errorprone.apidiff.Diff \
              source/api_diff.proto < "$resource" > decoded.textproto
            protoc -Isource \
              --encode=devtools.staticanalysis.errorprone.apidiff.Diff \
              source/api_diff.proto < decoded.textproto > reencoded.binarypb
            cmp "$resource" reencoded.binarypb
          done

          mavenClasspath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath:${checkApiJar}:${dataflowJar}:${formatJar}:${protobufJar}"
          printf '%s\n' "$classpath" > build-classpath

          exports=""
          for package in api code comp file main model parser processing tree util; do
            exports="$exports --add-exports=jdk.compiler/com.sun.tools.javac.$package=ALL-UNNAMED"
          done
          printf '%s\n' "$exports" > module-exports

          mkdir classes
          ${buildJdk}/bin/javac -source 17 -target 17 -encoding UTF-8 \
            $exports -processor com.google.auto.service.processor.AutoServiceProcessor \
            -processorpath "$classpath" -cp "$classpath" \
            -d classes @java-sources
          mkdir -p classes/com/google/errorprone/bugpatterns/apidiff
          cp "$resources"/*.binarypb classes/com/google/errorprone/bugpatterns/apidiff/
        '';
      }
      {
        name = "check";
        script = ''
          cat > ErrorProneCoreSmoke.java <<'JAVA'
          import com.google.errorprone.bugpatterns.apidiff.ApiDiffProto;
          import com.sun.source.util.Plugin;
          import java.io.InputStream;
          import java.util.ServiceLoader;

          final class ErrorProneCoreSmoke {
              public static void main(String[] args) throws Exception {
                  String base = "com/google/errorprone/bugpatterns/apidiff/";
                  for (String name : new String[] {
                          "7to11diff", "8to11diff", "android", "android_java8"}) {
                      try (InputStream resource = ErrorProneCoreSmoke.class.getClassLoader()
                              .getResourceAsStream(base + name + ".binarypb")) {
                          if (resource == null ||
                                  ApiDiffProto.Diff.parseFrom(resource).getClassDiffCount() == 0) {
                              throw new AssertionError("Missing API snapshot: " + name);
                          }
                      }
                  }
                  boolean pluginFound = ServiceLoader.load(Plugin.class).stream()
                          .anyMatch(provider -> provider.type().getName()
                                  .equals("com.google.errorprone.ErrorProneJavacPlugin"));
                  if (!pluginFound) {
                      throw new AssertionError("Error Prone javac plugin is missing");
                  }
              }
          }
          JAVA

          classpath="classes:$(cat build-classpath)"
          ${buildJdk}/bin/javac --release 17 -proc:none -cp "$classpath" \
            ErrorProneCoreSmoke.java
          ${buildJdk}/bin/java $(cat module-exports) \
            -cp "$classpath:." ErrorProneCoreSmoke
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/com/google/errorprone/error_prone_core/${version}"
          mkdir -p "$destination" "$out/share/licenses/error-prone-core"
          ${buildJdk}/bin/jar --create \
            --file "$destination/error_prone_core-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp ${license} "$out/share/licenses/error-prone-core/LICENSE"
          cp -R source "$out/share/source"
        '';
      }
    ];
  }
