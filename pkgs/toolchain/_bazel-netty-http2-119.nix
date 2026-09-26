##! Netty HTTP/2 4.1.119 Maven module compiled from audited Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelNetty119,
}: let
  version = "4.1.119.Final";
  buildJdk = buildPackages.openjdk-17;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-codec-http2/${version}/netty-codec-http2-${version}-sources.jar"];
    hash = "sha256-8vOkq9DphFEXMHjau+bfCMYX80MA9jmdhExgrqIY15w=";
  };
  nettyModules = [
    bazelNetty119.common
    bazelNetty119.base
    bazelNetty119.codec
    bazelNetty119.codecJavaDeps
    bazelNetty119.transportExtras
    bazelNetty119.handler
    bazelNetty119.codecHttp
  ];
  modulePaths = builtins.concatStringsSep " " (builtins.map (module: "${module}/share/java") nettyModules);
in
  mkDerivation {
    pname = "bazel-netty-http2";
    inherit version;
    src = source;

    passthru.sourceTargets = ["io/netty/netty-codec-http2/${version}/netty-codec-http2-${version}.jar"];

    buildDeps =
      [
        buildJdk
        buildPackages.findutils
        buildPackages.python3
        buildPackages.unzip
      ]
      ++ nettyModules;
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
                      raise SystemExit(f"Compiled payload in Netty source: {member.filename}")
                  if b"\0" in archive.read(member):
                      raise SystemExit(f"Opaque payload in Netty source: {member.filename}")
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
          classpath=$(find ${modulePaths} -type f -name '*.jar' -print | sort | paste -sd:)
          javac -source 8 -target 8 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d classes @sources

          find source -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              destination="classes/''${resource#source/}"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done

          jar --create --file netty-codec-http2.jar --no-manifest \
            --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
      {
        name = "check";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"
          classpath=$(find ${modulePaths} -type f -name '*.jar' -print | sort | paste -sd:)

          cat > NettyHttp2Check.java <<'JAVA'
          import io.netty.handler.codec.http2.DefaultHttp2Headers;

          public final class NettyHttp2Check {
              public static void main(String[] args) {
                  DefaultHttp2Headers headers = new DefaultHttp2Headers();
                  headers.method("GET").path("/");
                  if (!"GET".contentEquals(headers.method()) || !"/".contentEquals(headers.path())) {
                      throw new AssertionError("HTTP/2 headers did not round trip");
                  }
              }
          }
          JAVA

          javac -source 8 -target 8 -cp "netty-codec-http2.jar:$classpath" NettyHttp2Check.java
          java -cp "netty-codec-http2.jar:$classpath:." NettyHttp2Check
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 netty-codec-http2.jar \
            "$out/maven/io/netty/netty-codec-http2/${version}/netty-codec-http2-${version}.jar"
        '';
      }
    ];
  }
