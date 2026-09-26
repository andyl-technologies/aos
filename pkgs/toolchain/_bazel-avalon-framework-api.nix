##! Avalon Framework API built from its historical Apache source release.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelLogkit,
  bazelLog4j,
}: let
  version = "4.1.5";
  buildJdk = buildPackages.openjdk-17;
  logkitJar = "${bazelLogkit}/maven/logkit/logkit/1.0.1/logkit-1.0.1.jar";
  log4jJar = "${bazelLog4j}/maven/log4j/log4j/1.2.17/log4j-1.2.17.jar";
in
  mkDerivation {
    pname = "bazel-avalon-framework-api";
    inherit version;
    src = fetchurl {
      urls = ["https://archive.apache.org/dist/avalon/framework/source/avalon-framework-${version}.src.tar.gz"];
      hash = "sha256-KewFT/XaXe3pjpAVb7LzA3xhegT5+idTqwNHGAMeBY0=";
    };

    buildDeps = [buildJdk buildPackages.python3 bazelLogkit bazelLog4j];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd avalon-framework

          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"),
          )
          for path in Path(".").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in Avalon source: {path}")
              if path.read_bytes()[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in Avalon source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes-api classes-impl
          find api/src/java -name '*.java' -print > java-sources
          javac --release 8 -proc:none -encoding ISO-8859-1 \
            -cp "${logkitJar}" -d classes-api @java-sources

          find impl/src/java -name '*.java' -print > impl-sources
          javac --release 8 -proc:none -encoding ISO-8859-1 \
            -cp "${logkitJar}:${log4jJar}:classes-api" -d classes-impl @impl-sources

          mkdir -p classes-logkit-bridge
          javac --release 8 -proc:none -encoding ISO-8859-1 \
            -cp "${logkitJar}:classes-api:classes-impl" -d classes-logkit-bridge \
            ${bazelLogkit}/share/sources/logkit/AvalonFormatter.java
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java" "$out/share/licenses/avalon-framework"
          jar --create --file "$out/share/java/avalon-framework-api-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes-api .
          jar --create --file "$out/share/java/avalon-framework-impl-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes-impl .

          # Publish the complete LogKit JAR after its Avalon compatibility
          # formatter has been compiled against the new framework API.
          mkdir -p "$out/maven/logkit/logkit/1.0.1"
          cp ${logkitJar} "$out/maven/logkit/logkit/1.0.1/logkit-1.0.1.jar"
          chmod u+w "$out/maven/logkit/logkit/1.0.1/logkit-1.0.1.jar"
          jar --update --file "$out/maven/logkit/logkit/1.0.1/logkit-1.0.1.jar" \
            --date=1980-01-01T00:00:02Z -C classes-logkit-bridge .
          cp LICENSE.txt "$out/share/licenses/avalon-framework/LICENSE.txt"
        '';
      }
    ];
  }
