##! Source-built ProGuard used by Bazel's fastutil trimming action.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
}: let
  version = "6.2.2";
  buildJdk = buildPackages.openjdk-17;
  gsonJar = "${bazelMavenBootstrap}/maven/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar";
in
  mkDerivation {
    pname = "bazel-proguard";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/net/sf/proguard/proguard-base/${version}/proguard-base-${version}-sources.jar"];
      hash = "sha256-6OBFUfb4S+vUbfal3eDnKKeN+N5GAYjZ5jMwfVICpKk=";
    };

    buildDeps = [
      buildJdk
      buildPackages.unzip
      buildPackages.findutils
      buildPackages.python3
      bazelMavenBootstrap
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          unzip -q "$src" -d source

          # Maven's sources classifier must not hide compiled payloads.
          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )
          for path in Path("source").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in ProGuard source: {path}")
              if path.read_bytes()[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in ProGuard source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir classes
          find source -name '*.java' -print > java-sources
          javac --release 8 -proc:none -cp ${gsonJar} -d classes @java-sources

          find source -type f ! -name '*.java' \
            ! -path 'source/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
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
          jar --create --file "$out/share/java/proguard-base-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
