##! Netty DNS and proxy 4.1.119 Maven modules compiled from Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelNetty119,
}: let
  version = "4.1.119.Final";
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "codec-dns";
      hash = "sha256-THMX6OaSPybXfRQhYmlp5iXDSqXWcgmvqzemqaW4Q8g=";
    }
    {
      name = "resolver-dns";
      hash = "sha256-pbCJ7438OPPEnwlRYmCv6ALEJcHxxRUBWn4KFXkePrY=";
    }
    {
      name = "handler-proxy";
      hash = "sha256-+z6oj7ilN8AEMC0KLblOR70Ivz5lsmmuA/wh+fcLqS0=";
    }
  ];
  sources = builtins.map (archive:
    archive
    // {
      src = fetchurl {
        urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-${archive.name}/${version}/netty-${archive.name}-${version}-sources.jar"];
        inherit (archive) hash;
      };
      target = "io/netty/netty-${archive.name}/${version}/netty-${archive.name}-${version}.jar";
    })
  archives;
  sourcePaths = builtins.concatStringsSep " " (builtins.map (source: toString source.src) sources);
  nettyModules = [
    bazelNetty119.common
    bazelNetty119.base
    bazelNetty119.codec
    bazelNetty119.transportExtras
    bazelNetty119.handler
    bazelNetty119.codecHttp
  ];
  modulePaths = builtins.concatStringsSep " " (builtins.map (module: "${module}/share/java") nettyModules);
  buildSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p source-${source.name} classes-${source.name}
      unzip -q ${source.src} -d source-${source.name}
      find source-${source.name} -name '*.java' ! -name module-info.java \
        -print > sources-${source.name}
      javac --release 8 -proc:none -encoding UTF-8 \
        -cp "$classpath" -d classes-${source.name} @sources-${source.name}

      find source-${source.name} -type f ! -name '*.java' \
        ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
          destination="classes-${source.name}/''${resource#source-${source.name}/}"
          mkdir -p "$(dirname "$destination")"
          cp "$resource" "$destination"
        done

      jar --create --file netty-${source.name}.jar --no-manifest \
        --date=1980-01-01T00:00:02Z -C classes-${source.name} .
      classpath="netty-${source.name}.jar:$classpath"
    '')
    sources);
  installSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      install -Dm644 netty-${source.name}.jar "$out/maven/${source.target}"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-netty-dns-proxy";
    inherit version;
    src = (builtins.head sources).src;

    passthru.sourceTargets = builtins.map (source: source.target) sources;

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
          python3 - ${sourcePaths} <<'PY'
          import sys
          from zipfile import ZipFile

          compiled_suffixes = (
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          )
          for source_path in sys.argv[1:]:
              with ZipFile(source_path) as archive:
                  for member in archive.infolist():
                      if member.is_dir():
                          continue
                      if member.filename.lower().endswith(compiled_suffixes):
                          raise SystemExit(f"Compiled payload in {source_path}: {member.filename}")
                      if b"\0" in archive.read(member):
                          raise SystemExit(f"Opaque payload in {source_path}: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"
          classpath=$(find ${modulePaths} -type f -name '*.jar' -print | sort | paste -sd:)

          ${buildSources}
        '';
      }
      {
        name = "check";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"
          classpath=$(find ${modulePaths} -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="netty-codec-dns.jar:netty-resolver-dns.jar:netty-handler-proxy.jar:$classpath"

          cat > NettyDnsProxyCheck.java <<'JAVA'
          import io.netty.handler.codec.dns.DefaultDnsQuestion;
          import io.netty.handler.codec.dns.DnsRecordType;
          import io.netty.handler.proxy.HttpProxyHandler;
          import io.netty.resolver.dns.DnsNameResolver;
          import java.net.InetSocketAddress;

          public final class NettyDnsProxyCheck {
              public static void main(String[] args) {
                  DefaultDnsQuestion question = new DefaultDnsQuestion("example.com", DnsRecordType.A);
                  if (!"example.com.".equals(question.name())) {
                      throw new AssertionError("DNS question failed");
                  }
                  new HttpProxyHandler(new InetSocketAddress("localhost", 8080));
                  if (DnsNameResolver.class.getName().isEmpty()) {
                      throw new AssertionError("DNS resolver class missing");
                  }
              }
          }
          JAVA

          javac --release 8 -cp "$classpath" NettyDnsProxyCheck.java
          java -cp "$classpath:." NettyDnsProxyCheck
        '';
      }
      {
        name = "install";
        script = installSources;
      }
    ];
  }
