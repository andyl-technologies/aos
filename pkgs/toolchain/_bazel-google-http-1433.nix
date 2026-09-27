##! Google HTTP 1.43.3 Maven libraries compiled from audited Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelGoogleHttp,
}: let
  version = "1.43.3";
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "google-http-client";
      hash = "sha256-PTl9Bg6a4OinFyH/g27WKe5myBuTJuTypaqJKujDo/k=";
    }
    {
      name = "google-http-client-gson";
      hash = "sha256-5vZdNFm1+JB/OinCmZFtse/VaIP4zkWvGw8ngDYYGvU=";
    }
  ];
  sources =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = ["https://repo.maven.apache.org/maven2/com/google/http-client/${archive.name}/${version}/${archive.name}-${version}-sources.jar"];
            inherit (archive) hash;
          };
        }
    )
    archives;
  sourcePaths = builtins.concatStringsSep " " (builtins.map (source: toString source.src) sources);
  targets =
    builtins.map (
      source: "com/google/http-client/${source.name}/${version}/${source.name}-${version}.jar"
    )
    sources;
  buildSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p source-${source.name} classes-${source.name}
      unzip -q ${source.src} -d source-${source.name}
      find source-${source.name} -name '*.java' -print > sources-${source.name}
      javac --release 17 -proc:none -encoding UTF-8 \
        -cp "$classpath" -d classes-${source.name} @sources-${source.name}

      find source-${source.name} -type f ! -name '*.java' \
        ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
          relative=''${resource#source-${source.name}/}
          destination="classes-${source.name}/$relative"
          mkdir -p "$(dirname "$destination")"
          cp "$resource" "$destination"
        done

      jar --create --file ${source.name}.jar --no-manifest \
        --date=1980-01-01T00:00:02Z -C classes-${source.name} .
      classpath="$PWD/${source.name}.jar:$classpath"
    '')
    sources);
  installSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      install -Dm644 ${source.name}.jar \
        "$out/maven/com/google/http-client/${source.name}/${version}/${source.name}-${version}.jar"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-google-http-modern";
    inherit version;
    src = (builtins.head sources).src;

    passthru.sourceTargets = targets;

    buildDeps = [
      buildJdk
      bazelMavenBootstrap
      bazelGoogleHttp
      buildPackages.findutils
      buildPackages.python3
      buildPackages.unzip
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - ${sourcePaths} <<'PY'
          import sys
          from zipfile import ZipFile

          compiled_suffixes = (
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          )
          for path in sys.argv[1:]:
              with ZipFile(path) as archive:
                  for member in archive.infolist():
                      if member.is_dir():
                          continue
                      if member.filename.lower().endswith(compiled_suffixes):
                          raise SystemExit(f"Compiled payload in Google HTTP source: {member.filename}")
                      if b"\0" in archive.read(member):
                          raise SystemExit(f"Opaque payload in Google HTTP source: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mavenClasspath=$(find ${bazelMavenBootstrap}/maven ${bazelGoogleHttp}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath"

          ${buildSources}
        '';
      }
      {
        name = "check";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"
          mavenClasspath=$(find ${bazelMavenBootstrap}/maven ${bazelGoogleHttp}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$PWD/google-http-client-gson.jar:$PWD/google-http-client.jar"
          classpath="$classpath:$mavenClasspath"

          cat > GoogleHttpCheck.java <<'JAVA'
          import com.google.api.client.json.gson.GsonFactory;
          import java.util.Map;

          public final class GoogleHttpCheck {
              public static void main(String[] args) throws Exception {
                  Map<?, ?> parsed = GsonFactory.getDefaultInstance()
                      .createJsonParser("{\"ready\":true}").parse(Map.class);
                  if (!Boolean.TRUE.equals(parsed.get("ready"))) {
                      throw new AssertionError("Google HTTP JSON parser failed");
                  }
              }
          }
          JAVA

          javac --release 17 -cp "$classpath" GoogleHttpCheck.java
          java -cp "$classpath:." GoogleHttpCheck
        '';
      }
      {
        name = "install";
        script = installSources;
      }
    ];
  }
