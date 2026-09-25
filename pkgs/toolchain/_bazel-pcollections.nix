##! PCollections 4.0.1 built from source without its published precompiled module.
{
  mkDerivation,
  fetchgit,
  buildPackages,
}: let
  version = "4.0.1";
  buildJdk = buildPackages.openjdk-17;
  source = fetchgit {
    url = "https://github.com/hrldcpr/pcollections.git";
    ref = "v${version}";
    rev = "0028f87c26fdd62bfaeb9c9f030b4f288103aaa4";
    hash = "sha256-GF8jZ2VGYodHaRSxyJW964M3ONKoGCq/UNZAdE3Ij6M=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/src/main/"
      "/LICENSE"
    ];
  };
in
  mkDerivation {
    pname = "bazel-pcollections";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      buildPackages.findutils
      buildPackages.python3
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - "$src" <<'PY'
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
          find "$src/src/main/java" -name '*.java' -print | sort > java-sources
          javac --release 17 -proc:none -encoding UTF-8 \
            -d classes @java-sources

          if test -d "$src/src/main/resources"; then
            cp -R "$src/src/main/resources/." classes/
          fi
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java" "$out/share/licenses/pcollections"
          jar --create --file "$out/share/java/pcollections-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp "$src/LICENSE" "$out/share/licenses/pcollections/LICENSE"
        '';
      }
    ];
  }
