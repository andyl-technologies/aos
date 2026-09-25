##! Google Java Format compiled from source for Bazel's Maven graph.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
}: let
  version = "1.19.1";
  buildJdk = buildPackages.openjdk-21;
  src = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/google/googlejavaformat/google-java-format/${version}/google-java-format-${version}-sources.jar"];
    hash = "sha256-FJcM9EoGrp5+Fg7ZiIx9j/oinb29xXrUcl1c6qqacnM=";
  };
in
  mkDerivation {
    pname = "bazel-google-java-format";
    inherit version src;

    buildDeps = [
      buildJdk
      bazelMavenBootstrap
      buildPackages.unzip
      buildPackages.findutils
      buildPackages.python3
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          mkdir source
          unzip -q "$src" -d source
          python3 - source <<'PY'
          from pathlib import Path
          import sys

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )
          for path in Path(sys.argv[1]).rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in Google Java Format source: {path}")
              if path.read_bytes()[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in Google Java Format source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          classpath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          find source -type f -name '*.java' ! -name module-info.java \
            -print > java-sources
          test -s java-sources

          # The Java 21 visitor uses preview syntax and javac's own tree APIs.
          moduleExports=""
          for package in api code file parser tree util; do
            moduleExports="$moduleExports --add-exports=jdk.compiler/com.sun.tools.javac.$package=ALL-UNNAMED"
          done
          mkdir classes
          javac --enable-preview -source 21 -target 21 -encoding UTF-8 \
            -proc:none $moduleExports -cp "$classpath" -d classes @java-sources

          find source -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              relative=''${resource#source/}
              destination="classes/$relative"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done

          cat > manifest <<'EOF'
          Main-Class: com.google.googlejavaformat.java.Main

          EOF
          jar --create --file google-java-format.jar --manifest manifest \
            --date=1980-01-01T00:00:02Z -C classes .
          java --enable-preview $moduleExports \
            -cp "google-java-format.jar:$classpath" \
            com.google.googlejavaformat.java.Main --version
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 google-java-format.jar \
            "$out/maven/com/google/googlejavaformat/google-java-format/${version}/google-java-format-${version}.jar"
        '';
      }
    ];
  }
