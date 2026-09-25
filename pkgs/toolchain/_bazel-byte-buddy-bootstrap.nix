##! Byte Buddy classes compiled from a source-only checkout for Java bootstrap tools.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  bazelAsm,
  bazelJna,
  bazelMavenBootstrap,
}: let
  version = "1.10.22";
  buildJdk = buildPackages.openjdk-17;
  asmSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/ow2/asm/asm/9.2/asm-9.2-sources.jar"];
    hash = "sha256-gegHAQYx8OgHSw+4XoCv1u+71+SzaUqtGelEwXGYD7c=";
  };
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

    buildDeps = [buildJdk bazelAsm bazelJna bazelMavenBootstrap buildPackages.findutils buildPackages.python3 buildPackages.unzip];
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

          python3 - ${asmSource} <<'PY'
          import sys
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
                      raise SystemExit(f"Compiled payload in ASM source: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes agent-classes relocated-asm-classes relocated-asm-source
          find "$src/byte-buddy-dep/src/main/java" -type f -name '*.java' \
            -print > java-sources
          classpath="${bazelAsm}/share/java/asm-9.2.jar:${bazelAsm}/share/java/asm-commons-9.2.jar"
          classpath="$classpath:${bazelMavenBootstrap}/maven/com/google/code/findbugs/findbugs-annotations/3.0.1/findbugs-annotations-3.0.1.jar"
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d classes @java-sources

          find "$src/byte-buddy-agent/src/main/java" -type f -name '*.java' \
            -print > agent-sources
          agentClasspath="${bazelJna}/share/java/jna-5.3.1.jar:${bazelJna}/share/java/jna-platform-5.3.1.jar"
          agentClasspath="$agentClasspath:${bazelMavenBootstrap}/maven/com/google/code/findbugs/findbugs-annotations/3.0.1/findbugs-annotations-3.0.1.jar"
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "$agentClasspath" -d agent-classes @agent-sources

          unzip -q ${asmSource} -d relocated-asm-source
          find relocated-asm-source -type f -name '*.java' \
            ! -name module-info.java -print > asm-sources
          while IFS= read -r sourceFile; do
            sed -i 's/org\.objectweb\.asm/net.bytebuddy.jar.asm/g' "$sourceFile"
          done < asm-sources
          javac --release 8 -proc:none -encoding UTF-8 \
            -d relocated-asm-classes @asm-sources
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          jar --create --file "$out/share/java/byte-buddy-dep-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cat > agent-manifest <<'EOF'
          Manifest-Version: 1.0
          Premain-Class: net.bytebuddy.agent.Installer
          Agent-Class: net.bytebuddy.agent.Installer
          Can-Redefine-Classes: true
          Can-Retransform-Classes: true

          EOF
          jar --create --file "$out/share/java/byte-buddy-agent-${version}.jar" \
            --manifest agent-manifest --date=1980-01-01T00:00:02Z \
            -C agent-classes .
          jar --create --file "$out/share/java/byte-buddy-shaded-asm-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z \
            -C relocated-asm-classes .
        '';
      }
    ];
  }
