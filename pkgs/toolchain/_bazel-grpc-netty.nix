##! gRPC Netty transport classes built from Java source.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelNettyCommon,
  bazelNettyBase,
  bazelNettyCodec,
  bazelNettyTransportExtras,
  bazelNettyHandler,
  bazelNettyCodecHttp,
  bazelNettyHttp2Proxy,
}: let
  version = "1.48.1";
  buildJdk = buildPackages.openjdk-17;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/grpc/grpc-netty/${version}/grpc-netty-${version}-sources.jar"];
    hash = "sha256-TnTT4/EiPjVWTZ2VIqw+36SXP37Ko6N2udJhEz++R5U=";
  };
in
  mkDerivation {
    pname = "bazel-grpc-netty";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      bazelMavenBootstrap
      bazelNettyCommon
      bazelNettyBase
      bazelNettyCodec
      bazelNettyTransportExtras
      bazelNettyHandler
      bazelNettyCodecHttp
      bazelNettyHttp2Proxy
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
                      raise SystemExit(f"Compiled payload in gRPC Netty source: {member.filename}")
                  if b"\0" in source.read(member):
                      raise SystemExit(f"Opaque payload in gRPC Netty source: {member.filename}")
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

          classpath=$(find \
            ${bazelMavenBootstrap}/maven \
            ${bazelNettyCommon}/share/java \
            ${bazelNettyBase}/share/java \
            ${bazelNettyCodec}/share/java \
            ${bazelNettyTransportExtras}/share/java \
            ${bazelNettyHandler}/share/java \
            ${bazelNettyCodecHttp}/share/java \
            ${bazelNettyHttp2Proxy}/share/java \
            -type f -name '*.jar' -print | sort | paste -sd:)

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
          jar --create --file "$out/share/java/grpc-netty-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
