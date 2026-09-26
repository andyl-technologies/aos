##! Error Prone check API compiled from its complete Java source archive.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelErrorProneDataflow,
}: let
  version = "2.36.0";
  buildJdk = buildPackages.openjdk-17;
  dataflowVersion = bazelErrorProneDataflow.version;
  dataflowJar = "${bazelErrorProneDataflow}/maven/io/github/eisop/dataflow-errorprone/${dataflowVersion}/dataflow-errorprone-${dataflowVersion}.jar";

  license = fetchurl {
    urls = ["https://raw.githubusercontent.com/google/error-prone/ab522c7dcac5e83b84828d5670595e5582d71fb3/COPYING"];
    hash = "sha256-z8d0m5b2O9McPEK1xHG/dWgUBT6EfBDz6wA0F7xSPTA=";
  };
in
  mkDerivation {
    pname = "bazel-error-prone-check-api";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_check_api/${version}/error_prone_check_api-${version}-sources.jar"];
      hash = "sha256-RBTgPTUTPHFp7RuNGCQ/6N9YMxqyq5TT1IUoJGy2yBA=";
    };

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.findutils
      bazelMavenBootstrap
      bazelErrorProneDataflow
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
                      raise SystemExit(f"Unsafe Error Prone check API source: {path}")
                  if member.is_dir():
                      continue

                  data = archive.read(member)
                  if path.suffix.lower() in compiled_suffixes or data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Error Prone check API source: {path}")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 189:
              raise SystemExit(f"Expected 189 Error Prone check API sources, found {len(sources)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mavenClasspath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath:${dataflowJar}"
          printf '%s\n' "$classpath" > build-classpath

          exports=""
          for package in api code comp file main model parser processing tree util; do
            exports="$exports --add-exports=jdk.compiler/com.sun.tools.javac.$package=ALL-UNNAMED"
          done
          printf '%s\n' "$exports" > module-exports

          mkdir -p classes/com/google/errorprone
          ${buildJdk}/bin/javac -source 17 -target 17 -proc:none -encoding UTF-8 \
            $exports -cp "$classpath" -d classes @java-sources
          cp source/com/google/errorprone/errors.properties \
            classes/com/google/errorprone/errors.properties
        '';
      }
      {
        name = "check";
        script = ''
          cat > ErrorProneCheckApiSmoke.java <<'JAVA'
          import com.google.errorprone.VisitorState;

          final class ErrorProneCheckApiSmoke {
              public static void main(String[] args) throws Exception {
                  Class.forName("com.google.errorprone.bugpatterns.BugChecker");
                  if (VisitorState.class.getResourceAsStream("errors.properties") == null) {
                      throw new AssertionError("Error Prone messages are missing");
                  }
              }
          }
          JAVA

          classpath="classes:$(cat build-classpath)"
          ${buildJdk}/bin/javac --release 17 -proc:none -cp "$classpath" \
            -d classes ErrorProneCheckApiSmoke.java
          ${buildJdk}/bin/java $(cat module-exports) \
            -cp "$classpath" ErrorProneCheckApiSmoke
          rm classes/ErrorProneCheckApiSmoke.class
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/com/google/errorprone/error_prone_check_api/${version}"
          mkdir -p "$destination" "$out/share/licenses/error-prone-check-api"
          ${buildJdk}/bin/jar --create \
            --file "$destination/error_prone_check_api-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp ${license} "$out/share/licenses/error-prone-check-api/LICENSE"
          cp -R source "$out/share/source"
        '';
      }
    ];
  }
