##! Netty codec's optional Java libraries built from audited source archives.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelJbossModules,
  bazelNettyCommon,
  bazelNettyBase,
  bazelMavenBootstrap,
  version ? "4.1.93.Final",
  brotliVersion ? "1.11.0",
  brotliServiceHash ? "sha256-fje+wvf0jtzD5OifSCm3kGhDF+gbl8BGk3dcsMZ8rhk=",
  brotliHash ? "sha256-TVjrwIBTYRHJx9OwsZGrfq37hAqAoXOb0VRdKf1nFkE=",
}: let
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "jzlib";
      sourceVersion = "1.1.3";
      mavenPath = "com/jcraft/jzlib";
      hash = "sha256-NevWeUHOcCTm59gLYKQlKpaH+g+QmnB5rJBL72wWWM8=";
    }
    {
      name = "compress-lzf";
      sourceVersion = "1.0.3";
      mavenPath = "com/ning/compress-lzf";
      hash = "sha256-EcRslnhuUTaspTUnjl4nynRTMZ4eGdeuJb8F1ACLMzk=";
    }
    {
      name = "lz4";
      sourceVersion = "1.3.0";
      mavenPath = "net/jpountz/lz4/lz4";
      hash = "sha256-lW3ybKK8oxMaV4aI4wDa6u9OmeeUUWvbzFJy6ATG9O4=";
    }
    {
      name = "lzma-java";
      sourceVersion = "1.3";
      mavenPath = "com/github/jponge/lzma-java";
      hash = "sha256-P1j+AAsgcM30CPDM9K4HGAuDz930hdxKCaQzz+t4geI=";
    }
    {
      name = "protobuf-javanano";
      sourceVersion = "3.0.0-alpha-5";
      mavenPath = "com/google/protobuf/nano/protobuf-javanano";
      hash = "sha256-0Z9VQ2jzYLxA0f4jjd/wJ+5Qe60iGD+rtFxIoN+LA3s=";
    }
    {
      name = "jboss-marshalling";
      sourceVersion = "2.0.5.Final";
      mavenPath = "org/jboss/marshalling/jboss-marshalling";
      hash = "sha256-gzxWojVxeV4MbpXx77NSZPjiR56AHdSh6fmkUP21b3g=";
    }
    {
      name = "service";
      sourceVersion = brotliVersion;
      mavenPath = "com/aayushatharva/brotli4j/service";
      hash = brotliServiceHash;
    }
    {
      name = "brotli4j";
      sourceVersion = brotliVersion;
      mavenPath = "com/aayushatharva/brotli4j/brotli4j";
      hash = brotliHash;
    }
  ];
  sources =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = ["https://repo.maven.apache.org/maven2/${archive.mavenPath}/${archive.sourceVersion}/${archive.name}-${archive.sourceVersion}-sources.jar"];
            inherit (archive) hash;
          };
        }
    )
    archives;
  sourcePaths = builtins.concatStringsSep " " (builtins.map (source: toString source.src) sources);
  unpackSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir "source-${source.name}"
      unzip -q ${source.src} -d "source-${source.name}"
    '')
    sources);
  buildModules = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir "classes-${source.name}"
      find "source-${source.name}" -name '*.java' \
        ! -name module-info.java -print > "sources-${source.name}"
      javac -source 17 -target 17 -proc:none -encoding UTF-8 \
        -cp "$classpath" -d "classes-${source.name}" @"sources-${source.name}"

      find "source-${source.name}" -type f ! -name '*.java' \
        ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
          relative=''${resource#source-${source.name}/}
          destination="classes-${source.name}/$relative"
          mkdir -p "$(dirname "$destination")"
          cp "$resource" "$destination"
        done
      jar --create --file "jars/${source.name}-${source.sourceVersion}.jar" \
        --no-manifest --date=1980-01-01T00:00:02Z -C "classes-${source.name}" .
      classpath="classes-${source.name}:$classpath"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-netty-codec-java-deps";
    inherit version;
    src = (builtins.head sources).src;

    buildDeps = [
      buildJdk
      bazelJbossModules
      bazelNettyCommon
      bazelNettyBase
      bazelMavenBootstrap
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
          nettyBaseClasspath=$(find ${bazelNettyBase}/share/java \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath:$nettyBaseClasspath"
          classpath="$classpath:${bazelNettyCommon}/share/java/netty-common-${version}.jar"
          classpath="$classpath:${bazelJbossModules}/share/java/jboss-modules-${bazelJbossModules.version}.jar"

          ${buildModules}
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
