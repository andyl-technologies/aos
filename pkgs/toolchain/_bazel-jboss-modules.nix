##! JBoss Modules built from a Git checkout without compiled source-JAR members.
{
  mkDerivation,
  fetchgit,
  buildPackages,
}: let
  version = "1.12.0.Final";
  buildJdk = buildPackages.openjdk-17;
  source = fetchgit {
    url = "https://github.com/jboss-modules/jboss-modules.git";
    ref = version;
    rev = "c2ff4fec63c94d1efe70c8a774e8e63470d67cad";
    name = "jboss-modules-${version}-source-only";
    hash = "sha256-+tfTqFvVldJQRIzClOmtSXa9CqE0S94J3MQ8rbFleTk=";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    # The older published source JAR includes compiled Java 9 classes. This
    # Git tag supplies their Java 9 source for a JDK 17 build.
    sparsePatterns = [
      "/*"
      "!*.class"
      "!*.jar"
      "!*.so"
      "!*.dylib"
      "!*.dll"
      "!*.a"
      "!*.o"
      "!*.exe"
      "!*.bin"
      "!*.wasm"
      "!*.zip"
      "!*.tar"
      "!*.gz"
      "!*.xz"
    ];
  };
in
  mkDerivation {
    pname = "bazel-jboss-modules";
    inherit version;
    src = source;

    buildDeps = [buildJdk buildPackages.findutils buildPackages.python3];
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
                  raise SystemExit(f"Opaque payload in JBoss Modules source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes
          find "$src/src/main/java" -name '*.java' \
            ! -name module-info.java -print | while IFS= read -r sourceFile; do
              relative=''${sourceFile#"$src/src/main/java/"}
              if test ! -f "$src/src/main/java9/$relative"; then
                echo "$sourceFile"
              fi
            done > java-sources
          find "$src/src/main/java9" -name '*.java' \
            ! -name module-info.java -print >> java-sources
          javac -source 17 -target 17 -proc:none -encoding UTF-8 \
            -d classes @java-sources

          find "$src/src/main/resources" -type f -print | while IFS= read -r resource; do
            relative=''${resource#"$src/src/main/resources/"}
            destination="classes/$relative"
            mkdir -p "$(dirname "$destination")"
            cp "$resource" "$destination"
          done
          cat > classes/org/jboss/modules/version.properties <<'EOF'
          jarName=jboss-modules
          version=${version}
          EOF
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          cat > manifest <<'EOF'
          Manifest-Version: 1.0
          Main-Class: org.jboss.modules.Main

          EOF
          jar --create --file "$out/share/java/jboss-modules-${version}.jar" \
            --manifest manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
