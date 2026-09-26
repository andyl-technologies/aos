##! Netty's buffer, resolver, and transport Java modules built from source.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelNettyCommon,
  bazelMavenBootstrap,
  bazelLog4j,
  bazelLegacyJavaHttp,
  bazelBlockHound,
  bazelByteBuddy,
}: let
  version = "4.1.93.Final";
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "buffer";
      hash = "sha256-aJVDZUrjmeTlLvW2EiaEgpQe00yYoss5TcU7G7xbucE=";
    }
    {
      name = "resolver";
      hash = "sha256-laQVXoAVzKhETienb9ZwxvDAB/gr0eBfetTRdOckEl0=";
    }
    {
      name = "transport";
      hash = "sha256-XlEYYkfTYVVHi0wRB5XH/4aqr753Uy73seSF6wiYkvY=";
    }
  ];
  sources =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-${archive.name}/${version}/netty-${archive.name}-${version}-sources.jar"];
            inherit (archive) hash;
          };
        }
    )
    archives;
  sourcePaths = builtins.concatStringsSep " " (builtins.map (source: toString source.src) sources);
  moduleNames = builtins.concatStringsSep " " (builtins.map (source: source.name) sources);
  unpackSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir "source-${source.name}"
      unzip -q ${source.src} -d "source-${source.name}"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-netty-base";
    inherit version;
    src = (builtins.head sources).src;

    buildDeps = [
      buildJdk
      bazelNettyCommon
      bazelMavenBootstrap
      bazelLog4j
      bazelLegacyJavaHttp
      bazelBlockHound
      bazelByteBuddy
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
          for source_path in sys.argv[1:]:
              with ZipFile(source_path) as source:
                  for member in source.infolist():
                      if member.is_dir():
                          continue
                      if member.filename.lower().endswith(compiled_suffixes):
                          raise SystemExit(f"Compiled payload in {source_path}: {member.filename}")
                      if b"\0" in source.read(member):
                          raise SystemExit(f"Opaque payload in {source_path}: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          ${unpackSources}
          mkdir -p jars

          mavenClasspath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath:${bazelNettyCommon}/share/java/netty-common-${version}.jar"
          classpath="$classpath:${bazelLog4j}/maven/log4j/log4j/1.2.17/log4j-1.2.17.jar"
          classpath="$classpath:${bazelLegacyJavaHttp}/maven/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"
          classpath="$classpath:${bazelBlockHound}/share/java/blockhound-1.0.6.RELEASE.jar"
          classpath="$classpath:${bazelByteBuddy}/share/java/byte-buddy-dep-1.10.22.jar"
          classpath="$classpath:${bazelByteBuddy}/share/java/byte-buddy-shaded-asm-1.10.22.jar"

          for module in ${moduleNames}; do
            mkdir "classes-$module"
            find "source-$module" -name '*.java' \
              ! -name module-info.java -print > "sources-$module"
            javac -source 8 -target 8 -proc:none -encoding UTF-8 \
              -cp "$classpath" -d "classes-$module" @"sources-$module"

            find "source-$module" -type f ! -name '*.java' \
              ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
                relative=''${resource#source-$module/}
                destination="classes-$module/$relative"
                mkdir -p "$(dirname "$destination")"
                cp "$resource" "$destination"
              done
            jar --create --file "jars/netty-$module-${version}.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z -C "classes-$module" .
            classpath="classes-$module:$classpath"
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          cp jars/*.jar "$out/share/java/"
        '';
      }
    ];
  }
