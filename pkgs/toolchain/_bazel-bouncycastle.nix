##! Bouncy Castle Java modules needed by Netty's TLS handler.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.69";
  buildJdk = buildPackages.openjdk-17;
  archives = [
    {
      name = "bcprov-jdk15on";
      hash = "sha256-MtHMvVUq5YBqWhhd096ljwPBwaZhmDItVMST5quXxSg=";
    }
    {
      name = "bcutil-jdk15on";
      hash = "sha256-73hJ3zew8Xxok0QGFBi0tQrQZ//6zzjomhz4UG1poko=";
    }
    {
      name = "bcpkix-jdk15on";
      hash = "sha256-wIGOxrxP3PUH/AGHndj/RKN3eIvN0LuEhEGufx2UZrw=";
    }
    {
      name = "bctls-jdk15on";
      hash = "sha256-fFESXLzSNDCALLWN8TbZWej11J5FbhEkWqgG8cQWYvo=";
    }
  ];
  sources =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = ["https://repo.maven.apache.org/maven2/org/bouncycastle/${archive.name}/${version}/${archive.name}-${version}-sources.jar"];
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
    pname = "bazel-bouncycastle";
    inherit version;
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
            jar --create --file "jars/$module-${version}.jar" \
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
