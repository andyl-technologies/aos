##! PCollections 4.0.1 built from individually pinned source files.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "4.0.1";
  buildJdk = buildPackages.openjdk-17;
  revision = "0028f87c26fdd62bfaeb9c9f030b4f288103aaa4";
  sourceFiles = import ./_bazel-pcollections-sources.nix;
  sources = builtins.map (file:
    file
    // {
      src = fetchurl {
        urls = ["https://raw.githubusercontent.com/hrldcpr/pcollections/${revision}/${file.path}"];
        inherit (file) hash;
      };
    })
  sourceFiles;
  unpackSources = builtins.concatStringsSep "\n" (builtins.map (file: ''
      install -Dm644 ${file.src} "source/${file.path}"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-pcollections";
    inherit version;
    src = (builtins.head sources).src;

    buildDeps = [
      buildJdk
      buildPackages.findutils
      buildPackages.python3
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = unpackSources;
      }
      {
        name = "audit-source";
        script = ''
          python3 - source <<'PY'
          from pathlib import Path
          import sys

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          for path in Path(sys.argv[1]).rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes or b"\0" in path.read_bytes():
                  raise SystemExit(f"Opaque payload in PCollections source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes
          find source/src/main/java -name '*.java' \
            ! -name module-info.java -print | sort > java-sources
          javac --release 17 -proc:none -encoding UTF-8 \
            -d classes @java-sources

          if test -d source/src/main/resources; then
            cp -R source/src/main/resources/. classes/
          fi
        '';
      }
      {
        name = "check";
        script = ''
          cat > PCollectionsSourceSmoke.java <<'JAVA'
          import org.pcollections.HashTreePMap;
          import org.pcollections.PMap;

          final class PCollectionsSourceSmoke {
              public static void main(String[] args) {
                  PMap<String, Integer> original = HashTreePMap.empty();
                  PMap<String, Integer> updated = original.plus("value", 7);
                  if (!original.isEmpty() || updated.get("value") != 7) {
                      throw new AssertionError("Persistent map update failed");
                  }
              }
          }
          JAVA

          mkdir -p check-classes
          javac --release 17 -proc:none -cp classes \
            -d check-classes PCollectionsSourceSmoke.java
          java -cp classes:check-classes PCollectionsSourceSmoke
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java" "$out/share/licenses/pcollections"
          jar --create --file "$out/share/java/pcollections-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/LICENSE "$out/share/licenses/pcollections/LICENSE"
        '';
      }
    ];
  }
