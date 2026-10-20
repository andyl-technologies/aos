##! Commons Logging built from source with its legacy logging adapters.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelAvalonApi,
  bazelMailApi,
  bazelLog4j,
}: let
  version = "7.7.1";
  buildJdk = buildPackages.openjdk-17;
  commonsLoggingSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2-sources.jar"];
    hash = "sha256-RDR6z+WGBGFyjpyzMlHpc0W+Nvig39XFEwwXJVlFX0E=";
  };
in
  mkDerivation {
    pname = "bazel-legacy-java-http";
    inherit version;
    src = commonsLoggingSource;

    buildDeps = [
      buildJdk
      buildPackages.unzip
      buildPackages.findutils
      buildPackages.python3
      bazelMavenBootstrap
      bazelAvalonApi
      bazelMailApi
      bazelLog4j
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source-commons-logging
          (cd source-commons-logging && unzip -q ${commonsLoggingSource})

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
          for root in (Path("source-commons-logging"),):
              for path in root.rglob("*"):
                  if not path.is_file():
                      continue
                  if path.suffix.lower() in compiled_suffixes:
                      raise SystemExit(f"Compiled payload in Java source: {path}")
                  if path.read_bytes()[:8].startswith(compiled_signatures):
                      raise SystemExit(f"Compiled payload in Java source: {path}")
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
          classpath="$base_classpath:${bazelAvalonApi}/maven/logkit/logkit/1.0.1/logkit-1.0.1.jar"
          classpath="$classpath:${bazelAvalonApi}/share/java/avalon-framework-api-${bazelAvalonApi.version}.jar"
          classpath="$classpath:${bazelAvalonApi}/share/java/avalon-framework-impl-${bazelAvalonApi.version}.jar"
          classpath="$classpath:${bazelMailApi}/share/java/javax.mail-${bazelMailApi.version}.jar"
          classpath="$classpath:${bazelLog4j}/maven/log4j/log4j/1.2.17/log4j-1.2.17.jar"

          for module in commons-logging; do
            mkdir -p "classes-$module"
            find "source-$module" -name '*.java' \
              ! -name module-info.java -print > "sources-$module"
            javac --release 8 -proc:none -encoding ISO-8859-1 \
              -cp "$classpath" -d "classes-$module" @"sources-$module"

            # Service descriptors and package resources must accompany classes.
            find "source-$module" -type f ! -name '*.java' \
              ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
                relative=''${resource#source-$module/}
                destination="classes-$module/$relative"
                mkdir -p "$(dirname "$destination")"
                cp "$resource" "$destination"
              done
            classpath="classes-$module:$classpath"
          done
        '';
      }
      {
        name = "install";
        script = ''
          install -d "$out/maven/commons-logging/commons-logging/1.2"
          jar --create --file "$out/maven/commons-logging/commons-logging/1.2/commons-logging-1.2.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes-commons-logging .
        '';
      }
    ];
  }
