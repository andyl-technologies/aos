##! Google OAuth HTTP dependencies compiled from pinned Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelLegacyJavaHttp,
  bazelLog4j,
  bazelAvalonApi,
  bazelMailApi,
}: let
  version = "7.7.1";
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      target = "org/apache/httpcomponents/httpclient/4.5.13/httpclient-4.5.13.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/apache/httpcomponents/httpclient/4.5.13/httpclient-4.5.13-sources.jar";
      hash = "sha256-sekZT9g84TWDHig0ZzHZZEyyoI3qN62iqlbOuPGwxWY=";
    }
    {
      target = "com/google/http-client/google-http-client/1.42.0/google-http-client-1.42.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/http-client/google-http-client/1.42.0/google-http-client-1.42.0-sources.jar";
      hash = "sha256-BigivEZLgQpknZYXLDcBAq5RuHxMXFf3i1q8icOE1oc=";
    }
    {
      target = "com/google/http-client/google-http-client-gson/1.42.0/google-http-client-gson-1.42.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/http-client/google-http-client-gson/1.42.0/google-http-client-gson-1.42.0-sources.jar";
      hash = "sha256-WbWQMDzXj2aJmM8lJE5PvdcYrJHXIdkEz94iytrC+pk=";
    }
    {
      target = "com/google/http-client/google-http-client-apache-v2/1.42.0/google-http-client-apache-v2-1.42.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/http-client/google-http-client-apache-v2/1.42.0/google-http-client-apache-v2-1.42.0-sources.jar";
      hash = "sha256-lBG282JvyfsizP/67XbYaozLEiyDjZyI26u5FAFUqSE=";
    }
    {
      target = "com/google/auth/google-auth-library-oauth2-http/1.6.0/google-auth-library-oauth2-http-1.6.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/auth/google-auth-library-oauth2-http/1.6.0/google-auth-library-oauth2-http-1.6.0-sources.jar";
      hash = "sha256-83TmGepTt28Yje1e81lZVXOkBY0ToEl5GlIpRgmytuM=";
      autoValueProcessor = true;
    }
    {
      target = "com/google/oauth-client/google-oauth-client/1.34.1/google-oauth-client-1.34.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/oauth-client/google-oauth-client/1.34.1/google-oauth-client-1.34.1-sources.jar";
      hash = "sha256-zechp7F6jdiNyuH/Gr7Ezt4YbyfNVfLee6NHlEObZj0=";
    }
    {
      target = "com/google/api-client/google-api-client/1.35.2/google-api-client-1.35.2.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/api-client/google-api-client/1.35.2/google-api-client-1.35.2-sources.jar";
      hash = "sha256-36pREN0PaJAGuXqa7aD2z54WkURR/arfnUXjfBU2MVE=";
    }
    {
      target = "com/google/api-client/google-api-client-gson/1.35.2/google-api-client-gson-1.35.2.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/api-client/google-api-client-gson/1.35.2/google-api-client-gson-1.35.2-sources.jar";
      hash = "sha256-2XkcJwlscB/WcXDpPw+MTzt9FRqQnaoAXkezTVN55hc=";
    }
  ];
  sources = builtins.genList (
    index: let
      archive = builtins.elemAt archives index;
    in
      archive
      // {
        inherit index;
        src = fetchurl {
          urls = [archive.sourceUrl];
          inherit (archive) hash;
        };
      }
  ) (builtins.length archives);
  buildJars = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p source-${toString source.index} classes-${toString source.index}
      unzip -q ${source.src} -d source-${toString source.index}
      python3 - source-${toString source.index} <<'PY'
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
              raise SystemExit(f"Compiled payload in Google HTTP source: {path}")
          if path.read_bytes()[:8].startswith(compiled_signatures):
              raise SystemExit(f"Compiled payload in Google HTTP source: {path}")
      PY

      find source-${toString source.index} -type f -name '*.java' \
        ! -name module-info.java -print > sources-${toString source.index}.list
      javac --release 8 -encoding UTF-8 \
        ${
        if source.autoValueProcessor or false
        then ''          -processor com.google.auto.value.processor.AutoValueProcessor \
                    -processorpath "$classpath"''
        else "-proc:none"
      } \
        -cp "$classpath" -d classes-${toString source.index} \
        @sources-${toString source.index}.list

      find source-${toString source.index} -type f ! -name '*.java' \
        ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
          relative=''${resource#source-${toString source.index}/}
          destination="classes-${toString source.index}/$relative"
          mkdir -p "$(dirname "$destination")"
          cp "$resource" "$destination"
        done
      jar --create --file jar-${toString source.index}.jar --no-manifest \
        --date=1980-01-01T00:00:02Z -C classes-${toString source.index} .
      classpath="$PWD/jar-${toString source.index}.jar:$classpath"
    '')
    sources);
  installJars = builtins.concatStringsSep "\n" (builtins.map (source: ''
      install -D jar-${toString source.index}.jar "$out/maven/${source.target}"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-google-http";
    inherit version;
    src = builtins.head (builtins.map (source: source.src) sources);

    buildDeps = [
      buildJdk
      buildPackages.unzip
      buildPackages.findutils
      buildPackages.python3
      bazelMavenBootstrap
      bazelLegacyJavaHttp
      bazelLog4j
      bazelAvalonApi
      bazelMailApi
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          base_classpath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$base_classpath:${bazelLegacyJavaHttp}/maven/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"
          classpath="$classpath:${bazelLog4j}/maven/log4j/log4j/1.2.17/log4j-1.2.17.jar"
          classpath="$classpath:${bazelAvalonApi}/share/java/avalon-framework-api-${bazelAvalonApi.version}.jar"
          classpath="$classpath:${bazelAvalonApi}/share/java/avalon-framework-impl-${bazelAvalonApi.version}.jar"
          classpath="$classpath:${bazelMailApi}/share/java/javax.mail-${bazelMailApi.version}.jar"
          ${buildJars}
        '';
      }
      {
        name = "install";
        script = installJars;
      }
    ];
  }
