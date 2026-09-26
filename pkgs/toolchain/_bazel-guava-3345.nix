##! Guava 33.4.5 JRE compiled from audited Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelMavenModernAnnotations,
}: let
  version = "33.4.5-jre";
  buildJdk = buildPackages.openjdk-17;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/google/guava/guava/${version}/guava-${version}-sources.jar"];
    hash = "sha256-Gr3CSuT4TS9AIiVLCJqm3sJr0Pft8/suPTaR/WkQuyE=";
  };
in
  mkDerivation {
    pname = "bazel-guava";
    inherit version;
    src = source;

    passthru.sourceTargets = ["com/google/guava/guava/${version}/guava-${version}.jar"];

    buildDeps = [
      buildJdk
      bazelMavenBootstrap
      bazelMavenModernAnnotations
      buildPackages.findutils
      buildPackages.python3
      buildPackages.unzip
    ];
    runtimeDeps = [];

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
                      raise SystemExit(f"Compiled payload in Guava source: {member.filename}")
                  if b"\0" in archive.read(member):
                      raise SystemExit(f"Opaque payload in Guava source: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir source classes
          unzip -q ${source} -d source
          find source -name '*.java' ! -name module-info.java -print > sources
          classpath=$(find ${bazelMavenBootstrap}/maven \
            ${bazelMavenModernAnnotations}/maven -type f -name '*.jar' \
            -print | sort | paste -sd:)
          javac --release 17 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d classes @sources

          find source -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              destination="classes/''${resource#source/}"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done

          jar --create --file guava.jar --no-manifest \
            --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
      {
        name = "check";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"
          classpath=$(find ${bazelMavenBootstrap}/maven \
            ${bazelMavenModernAnnotations}/maven -type f -name '*.jar' \
            -print | sort | paste -sd:)

          cat > GuavaCheck.java <<'JAVA'
          import com.google.common.collect.ImmutableList;

          public final class GuavaCheck {
              public static void main(String[] args) {
                  ImmutableList<String> values = ImmutableList.of("a", "b");
                  if (values.size() != 2 || !"b".equals(values.get(1))) {
                      throw new AssertionError("Guava immutable list failed");
                  }
              }
          }
          JAVA

          javac --release 17 -cp "guava.jar:$classpath" GuavaCheck.java
          java -cp "guava.jar:$classpath:." GuavaCheck
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 guava.jar \
            "$out/maven/com/google/guava/guava/${version}/guava-${version}.jar"
        '';
      }
    ];
  }
