##! Netty HTTP/2 codec and proxy handler Java modules built from source.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelNettyCommon,
  bazelNettyBase,
  bazelNettyCodec,
  bazelNettyCodecJavaDeps,
  bazelNettyTransportExtras,
  bazelNettyHandler,
  bazelNettyCodecHttp,
}: let
  version = "4.1.93.Final";
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "handler-proxy";
      hash = "sha256-CX8cydLS+1RhHeGRKtm0Vqj/9aFaVUdEA16eXwbrbT4=";
    }
    {
      name = "codec-http2";
      hash = "sha256-FYO9xxNEa/LN3MTaft2juZ5E0gdNVo9z649KpBzmrnc=";
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
    pname = "bazel-netty-http2-proxy";
    inherit version;
    src = (builtins.head sources).src;

    buildDeps = [
      buildJdk
      bazelNettyCommon
      bazelNettyBase
      bazelNettyCodec
      bazelNettyCodecJavaDeps
      bazelNettyTransportExtras
      bazelNettyHandler
      bazelNettyCodecHttp
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

          classpath=$(find \
            ${bazelNettyCommon}/share/java \
            ${bazelNettyBase}/share/java \
            ${bazelNettyCodec}/share/java \
            ${bazelNettyCodecJavaDeps}/share/java \
            ${bazelNettyTransportExtras}/share/java \
            ${bazelNettyHandler}/share/java \
            ${bazelNettyCodecHttp}/share/java \
            -type f -name '*.jar' -print | sort | paste -sd:)

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
