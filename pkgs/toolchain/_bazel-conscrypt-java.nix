##! Conscrypt Java classes generated and compiled from source for Netty.
##! Its optional native JNI runtime remains outside this Java-only output.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "2.5.2";
  buildJdk = buildPackages.openjdk-17;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/conscrypt/conscrypt-openjdk-uber/${version}/conscrypt-openjdk-uber-${version}-sources.jar"];
    hash = "sha256-qh0C5lNR4gLoPs4GFLzhAiqh2m53MT73x2Y6tF+p46U=";
  };
  constantsGenerator = fetchurl {
    urls = ["https://raw.githubusercontent.com/google/conscrypt/56d9d2fd76bf4b00ebfe75b79360a83a3cd837b9/constants/src/gen/cpp/generate_constants.cc"];
    hash = "sha256-5BewPQrGUTHTapvsl1F+Dz6MfzvKQvwQMRYsuRPSUJQ=";
  };
in
  mkDerivation {
    pname = "bazel-conscrypt-java";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      buildPackages.boringssl
      buildPackages.gcc
      buildPackages.findutils
      buildPackages.python3
      buildPackages.unzip
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - ${source} ${constantsGenerator} <<'PY'
          import sys
          from pathlib import Path
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
                      raise SystemExit(f"Compiled payload in Conscrypt source: {member.filename}")
                  if b"\0" in source.read(member):
                      raise SystemExit(f"Opaque payload in Conscrypt source: {member.filename}")
          if b"\0" in Path(sys.argv[2]).read_bytes():
              raise SystemExit("Opaque payload in Conscrypt constants generator")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p source generated/org/conscrypt classes
          unzip -q ${source} -d source
          g++ -std=c++17 -I${buildPackages.boringssl}/include \
            ${constantsGenerator} -o generate-constants
          ./generate-constants > generated/org/conscrypt/NativeConstants.java

          find source generated -name '*.java' -print > java-sources
          javac -source 8 -target 8 -proc:none -encoding UTF-8 \
            -d classes @java-sources

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
          jar --create --file "$out/share/java/conscrypt-openjdk-uber-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
