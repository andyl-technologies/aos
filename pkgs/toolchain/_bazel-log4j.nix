##! Log4j 1.2 built from source for Avalon and Bazel's legacy adapters.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelMailApi,
}: let
  version = "1.2.17";
  buildJdk = buildPackages.openjdk-17;
in
  mkDerivation {
    pname = "bazel-log4j";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/log4j/log4j/${version}/log4j-${version}-sources.jar"];
      hash = "sha256-TZunh68WkqqIQXwqR6N6mBJdZFuRq1ViUtvuD0UiVJM=";
    };

    buildDeps = [
      buildJdk
      buildPackages.unzip
      buildPackages.findutils
      buildPackages.python3
      bazelMavenBootstrap
      bazelMailApi
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          unzip -q "$src" -d source

          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )
          for path in Path("source").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in Log4j source: {path}")
              if path.read_bytes()[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in Log4j source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          base_classpath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$base_classpath:${bazelMailApi}/share/java/javax.mail-${bazelMailApi.version}.jar"

          mkdir -p classes
          find source -name '*.java' ! -name module-info.java -print > java-sources
          javac --release 8 -proc:none -encoding ISO-8859-1 \
            -cp "$classpath" -d classes @java-sources

          find source -type f ! -name '*.java' \
            ! -path 'source/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              relative=''${resource#source/}
              destination="classes/$relative"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/maven/log4j/log4j/${version}"
          jar --create --file "$out/maven/log4j/log4j/${version}/log4j-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
