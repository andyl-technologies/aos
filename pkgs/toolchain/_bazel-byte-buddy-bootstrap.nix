##! Byte Buddy classes compiled from a source-only checkout for Java bootstrap tools.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  bazelAsm,
  bazelMavenBootstrap,
}: let
  version = "1.10.22";
  buildJdk = buildPackages.openjdk-17;
  source = fetchgit {
    url = "https://github.com/raphw/byte-buddy.git";
    ref = "byte-buddy-${version}";
    rev = "7ae30abfa24f0c13a06140f745c66ac8935c9a3f";
    name = "byte-buddy-${version}-source-only";
    hash = "sha256-Wt9vGWhA8A0On7UtQ4sR4N8UXewFFQ3HPimRB4c/0Bw=";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    # The published source JAR includes precompiled plugin classes, while the
    # agent source JAR carries Windows DLLs. Exclude their Git blobs up front.
    sparsePatterns = [
      "/*"
      "!*.class"
      "!*.jar"
      "!*.so"
      "!*.dll"
      "!*.dylib"
      "!*.a"
      "!*.o"
      "!*.exe"
      "!*.bin"
      "!*.zip"
      "!*.tar"
      "!*.gz"
      "!*.xz"
    ];
  };
in
  mkDerivation {
    pname = "bazel-byte-buddy-bootstrap";
    inherit version;
    src = source;

    buildDeps = [buildJdk bazelAsm bazelMavenBootstrap buildPackages.findutils buildPackages.python3];
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
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )
          for path in Path(sys.argv[1]).rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in Byte Buddy source: {path}")
              if path.read_bytes()[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in Byte Buddy source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes
          find "$src/byte-buddy-dep/src/main/java" -type f -name '*.java' \
            -print > java-sources
          classpath="${bazelAsm}/share/java/asm-9.2.jar:${bazelAsm}/share/java/asm-commons-9.2.jar"
          classpath="$classpath:${bazelMavenBootstrap}/maven/com/google/code/findbugs/findbugs-annotations/3.0.1/findbugs-annotations-3.0.1.jar"
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d classes @java-sources
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          jar --create --file "$out/share/java/byte-buddy-dep-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
