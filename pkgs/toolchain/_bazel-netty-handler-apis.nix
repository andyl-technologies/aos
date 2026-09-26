##! Source-built Jetty and tcnative Java APIs used by Netty's TLS handler.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "alpn-api";
      version = "1.1.2.v20150522";
      group = "org/eclipse/jetty/alpn";
      hash = "sha256-qY/79jiiQbWvp0yrWVsWIDeELOP/hX4bRrciDCJSiwQ=";
    }
    {
      name = "npn-api";
      version = "1.1.1.v20141010";
      group = "org/eclipse/jetty/npn";
      hash = "sha256-DZ7G/N4JT/eFUi/EA1duM4spIH9CZhVTmMkd77GiZFU=";
    }
    {
      name = "netty-tcnative-classes";
      version = "2.0.61.Final";
      group = "io/netty";
      hash = "sha256-tUI3C+atTXI+AVb8Qf/A2576MIMw5xrsGM3rDfw6RNA=";
    }
  ];
  sources =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = ["https://repo.maven.apache.org/maven2/${archive.group}/${archive.name}/${archive.version}/${archive.name}-${archive.version}-sources.jar"];
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
  installJars = builtins.concatStringsSep "\n" (builtins.map (source: ''
      cp "jars/${source.name}.jar" "$out/share/java/${source.name}-${source.version}.jar"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-netty-handler-apis";
    version = "4.1.93.Final";
    src = (builtins.head sources).src;

    buildDeps = [
      buildJdk
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
          classpath=.

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
            jar --create --file "jars/$module.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z -C "classes-$module" .
            classpath="classes-$module:$classpath"
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          ${installJars}
        '';
      }
    ];
  }
