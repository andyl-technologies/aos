##! Netty's HTTP codec classes built from Java source.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelNettyCommon,
  bazelNettyBase,
  bazelNettyCodec,
  bazelNettyCodecJavaDeps,
  bazelNettyHandler,
}: let
  version = "4.1.93.Final";
  buildJdk = buildPackages.openjdk-17;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-codec-http/${version}/netty-codec-http-${version}-sources.jar"];
    hash = "sha256-4Lw39eGpqROB5iaJFVX54sSYZLxyS98cjVXGi6nArJk=";
  };
in
  mkDerivation {
    pname = "bazel-netty-codec-http";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      bazelNettyCommon
      bazelNettyBase
      bazelNettyCodec
      bazelNettyCodecJavaDeps
      bazelNettyHandler
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
                      raise SystemExit(f"Compiled payload in Netty HTTP codec source: {member.filename}")
                  if b"\0" in source.read(member):
                      raise SystemExit(f"Opaque payload in Netty HTTP codec source: {member.filename}")
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
            ${bazelNettyCommon}/share/java \
            ${bazelNettyBase}/share/java \
            ${bazelNettyCodec}/share/java \
            ${bazelNettyCodecJavaDeps}/share/java \
            ${bazelNettyHandler}/share/java \
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
          jar --create --file "$out/share/java/netty-codec-http-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
