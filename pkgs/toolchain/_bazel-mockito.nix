##! Mockito core compiled from Java source for Bazel's Maven graph.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelByteBuddy114,
  bazelMavenBootstrap,
}: let
  version = "5.4.0";
  buildJdk = buildPackages.openjdk-17;
  src = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/mockito/mockito-core/${version}/mockito-core-${version}-sources.jar"];
    hash = "sha256-8h6xy7cBR3ujfEMLWpe6eOOzz3mlc3RD4Gs/Zb18k2Q=";
  };
  opentest4jSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/opentest4j/opentest4j/1.2.0/opentest4j-1.2.0-sources.jar"];
    hash = "sha256-tjSV73APsq8s3ujdaGWbJ4ImUAWCNKYC+e0dFLkJoag=";
  };
in
  mkDerivation {
    pname = "bazel-mockito";
    inherit version src;

    buildDeps = [
      buildJdk
      bazelByteBuddy114
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
          python3 - "$src" ${opentest4jSource} <<'PY'
          from pathlib import Path
          import sys
          from zipfile import ZipFile

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )
          for archive_path in sys.argv[1:]:
              with ZipFile(archive_path) as archive:
                  for member in archive.infolist():
                      if member.is_dir():
                          continue
                      if Path(member.filename).suffix.lower() in compiled_suffixes:
                          raise SystemExit(f"Compiled payload in Mockito source: {member.filename}")
                      if archive.read(member)[:8].startswith(compiled_signatures):
                          raise SystemExit(f"Compiled payload in Mockito source: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p opentest4j-source opentest4j-classes mockito-source mockito-classes
          unzip -q ${opentest4jSource} -d opentest4j-source
          unzip -q "$src" -d mockito-source

          find opentest4j-source -type f -name '*.java' -print > opentest4j-sources
          javac --release 17 -encoding UTF-8 -proc:none \
            -d opentest4j-classes @opentest4j-sources

          baseClasspath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          byteBuddyClasspath="${bazelByteBuddy114}/maven/net/bytebuddy/byte-buddy/1.14.5/byte-buddy-1.14.5.jar"
          byteBuddyAgent="${bazelByteBuddy114}/maven/net/bytebuddy/byte-buddy-agent/1.14.5/byte-buddy-agent-1.14.5.jar"
          classpath="opentest4j-classes:$byteBuddyClasspath:$byteBuddyAgent:$baseClasspath"
          find mockito-source -type f -name '*.java' \
            ! -name module-info.java -print > mockito-sources
          javac --release 17 -encoding UTF-8 -proc:none \
            -cp "$classpath" -d mockito-classes @mockito-sources

          find mockito-source -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              relative=''${resource#mockito-source/}
              destination="mockito-classes/$relative"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done

          # Mockito injects this class into the bootstrap class loader at
          # runtime. Upstream stores its compiled Java source as a .raw resource.
          dispatcher=mockito-classes/org/mockito/internal/creation/bytebuddy/inject/MockMethodDispatcher
          test -f "$dispatcher.class"
          cp "$dispatcher.class" "$dispatcher.raw"
          rm "$dispatcher.class"

          jar --create --file mockito-core.jar --no-manifest \
            --date=1980-01-01T00:00:02Z -C mockito-classes .

          cat > MockitoSmoke.java <<'JAVA'
          import static org.mockito.Mockito.mock;
          import static org.mockito.Mockito.when;

          public class MockitoSmoke {
              interface Greeting {
                  String say();
              }

              public static void main(String[] arguments) {
                  Greeting greeting = mock(Greeting.class);
                  when(greeting.say()).thenReturn("source-built");
                  if (!"source-built".equals(greeting.say())) {
                      throw new AssertionError("Mockito returned the wrong method value");
                  }
              }
          }
          JAVA
          javac -cp "mockito-core.jar:$classpath" MockitoSmoke.java
          java -javaagent:"$byteBuddyAgent" \
            -cp ".:mockito-core.jar:$classpath" MockitoSmoke
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 mockito-core.jar \
            "$out/maven/org/mockito/mockito-core/${version}/mockito-core-${version}.jar"
        '';
      }
    ];
  }
