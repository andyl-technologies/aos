##! Guava's intentionally empty ListenableFuture conflict-resolution artifact.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "9999.0-empty-to-avoid-conflict-with-guava";
  buildJdk = buildPackages.openjdk-17;
  sourcePom = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/google/guava/listenablefuture/${version}/listenablefuture-${version}.pom"];
    hash = "sha256-GNSx2yYVPU5VB5zh92ux/gXNuGLvmVSojLzE/zi4Z5s=";
  };
in
  mkDerivation {
    pname = "bazel-listenablefuture-empty";
    inherit version;
    src = sourcePom;

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - "$src" <<'PY'
          from pathlib import Path
          import sys

          source = Path(sys.argv[1]).read_bytes()
          if b"\0" in source or b"An empty artifact that Guava depends on" not in source:
              raise SystemExit("Unexpected ListenableFuture POM")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p empty
          # Bazel unpacks every staged JAR; a ZIP with no entries makes unzip fail.
          jar --create --file listenablefuture.jar \
            --date=1980-01-01T00:00:02Z -C empty .
          test -z "$(jar tf listenablefuture.jar | sed -n '/[.]class$/p')"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java" "$out/share/maven"
          cp listenablefuture.jar "$out/share/java/listenablefuture-${version}.jar"
          cp "$src" "$out/share/maven/listenablefuture-${version}.pom"
        '';
      }
    ];
  }
