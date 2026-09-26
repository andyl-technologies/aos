##! Google Auth 1.23.0 Maven libraries compiled from audited Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelGoogleHttp,
}: let
  version = "1.23.0";
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "google-auth-library-credentials";
      hash = "sha256-YVHHag2e976+YhNwu9gS6ScwC7/lsRQXwJvSmhxUUJs=";
    }
    {
      name = "google-auth-library-oauth2-http";
      hash = "sha256-9MAMrExyzTnQlX3/rV0ZxK1jGF5PvsPWIR+wzz9f228=";
    }
  ];
  sources =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = ["https://repo.maven.apache.org/maven2/com/google/auth/${archive.name}/${version}/${archive.name}-${version}-sources.jar"];
            inherit (archive) hash;
          };
        }
    )
    archives;
  sourcePaths = builtins.concatStringsSep " " (builtins.map (source: toString source.src) sources);
  targets =
    builtins.map (
      source: "com/google/auth/${source.name}/${version}/${source.name}-${version}.jar"
    )
    sources;
  buildSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p source-${source.name} classes-${source.name}
      unzip -q ${source.src} -d source-${source.name}
      find source-${source.name} -name '*.java' -print > sources-${source.name}
      javac --release 17 -encoding UTF-8 ${
        if source.name == "google-auth-library-oauth2-http"
        then "-processor com.google.auto.value.processor.AutoValueProcessor -processorpath \"$classpath\""
        else "-proc:none"
      } \
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
        "$out/maven/com/google/auth/${source.name}/${version}/${source.name}-${version}.jar"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-google-auth";
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
                          raise SystemExit(f"Compiled payload in Google Auth source: {member.filename}")
                      if b"\0" in archive.read(member):
                          raise SystemExit(f"Opaque payload in Google Auth source: {member.filename}")
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
          classpath="$PWD/google-auth-library-oauth2-http.jar"
          classpath="$classpath:$PWD/google-auth-library-credentials.jar:$mavenClasspath"

          cat > GoogleAuthCheck.java <<'JAVA'
          import com.google.auth.oauth2.AccessToken;
          import com.google.auth.oauth2.GoogleCredentials;
          import java.util.Date;

          public final class GoogleAuthCheck {
              public static void main(String[] args) {
                  AccessToken token = new AccessToken("source-built-token", new Date(0));
                  GoogleCredentials credentials = GoogleCredentials.create(token);
                  if (!credentials.getAccessToken().getTokenValue().equals("source-built-token")) {
                      throw new AssertionError("Google Auth token is unavailable");
                  }
              }
          }
          JAVA

          javac --release 17 -cp "$classpath" GoogleAuthCheck.java
          java -cp "$classpath:." GoogleAuthCheck
        '';
      }
      {
        name = "install";
        script = installSources;
      }
    ];
  }
