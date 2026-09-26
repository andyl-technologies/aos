##! Netty codec Java classes built with source-built optional libraries.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelNettyCommon,
  bazelNettyBase,
  bazelNettyCodecJavaDeps,
  bazelProtobufJava,
  bazelZstdJni155,
}: let
  version = "4.1.93.Final";
  buildJdk = buildPackages.openjdk-17;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-codec/${version}/netty-codec-${version}-sources.jar"];
    hash = "sha256-eQ7j7Rid5JC9OSoAXq2s03ulq0rxTUihoe5ESUAB6F0=";
  };
in
  mkDerivation {
    pname = "bazel-netty-codec";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      bazelMavenBootstrap
      bazelNettyCommon
      bazelNettyBase
      bazelNettyCodecJavaDeps
      bazelProtobufJava
      bazelZstdJni155
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
          with ZipFile(sys.argv[1]) as source:
              for member in source.infolist():
                  if member.is_dir():
                      continue
                  if member.filename.lower().endswith(compiled_suffixes):
                      raise SystemExit(f"Compiled payload in Netty codec source: {member.filename}")
                  if b"\0" in source.read(member):
                      raise SystemExit(f"Opaque payload in Netty codec source: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p source classes
          unzip -q ${source} -d source

          mavenClasspath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          baseClasspath=$(find ${bazelNettyBase}/share/java \
            -type f -name '*.jar' -print | sort | paste -sd:)
          codecDepsClasspath=$(find ${bazelNettyCodecJavaDeps}/share/java \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath:$baseClasspath:$codecDepsClasspath"
          classpath="$classpath:${bazelNettyCommon}/share/java/netty-common-${version}.jar"
          classpath="$classpath:${bazelProtobufJava}/share/java/protobuf-java-${bazelProtobufJava.version}.jar"
          classpath="$classpath:${bazelZstdJni155}/maven/com/github/luben/zstd-jni/1.5.5-11/zstd-jni-1.5.5-11.jar"

          find source/io -name '*.java' -print > java-sources
          javac -source 8 -target 8 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d classes @java-sources

          find source -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
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
          mkdir -p "$out/share/java"
          jar --create --file "$out/share/java/netty-codec-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
