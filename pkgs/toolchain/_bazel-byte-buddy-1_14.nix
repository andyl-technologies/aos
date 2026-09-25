##! Byte Buddy 1.14.5 and its agent built without checked-in class files or DLLs.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  bazelJna,
  bazelMavenBootstrap,
}: let
  version = "1.14.5";
  buildJdk = buildPackages.openjdk-17;
  legacyJdk = buildPackages.openjdk-8;

  source = fetchgit {
    url = "https://github.com/raphw/byte-buddy.git";
    ref = "byte-buddy-${version}";
    rev = "2074d31185d0fe8f41deb29a8f354967d2eb5c89";
    hash = "sha256-rvqdp+yk7UkU8zmTa4ThnZ8flHtPmlwlnrMgsU5iQ3s=";
    name = "byte-buddy-${version}-source-only";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    # The tag contains precompiled advice classes and Windows attach DLLs.
    # Their Java sources are fetched, while compiled Git blobs stay unfetched.
    sparsePatterns = [
      "/byte-buddy-dep/src/main/java/"
      "/byte-buddy-dep/src/main/java-6/"
      "/byte-buddy-agent/src/main/java/"
      "/LICENSE"
      "/pom.xml"
    ];
  };

  asmSources = [
    {
      component = "asm";
      hash = "sha256-K24S8No9BlumKKAkqIUasNW101AdrPzBh2kkMlD0934=";
    }
    {
      component = "asm-tree";
      hash = "sha256-4vS+re8cMgPk0A9kYFxK0J14+0X8bJTsNkl9Y+azeWk=";
    }
    {
      component = "asm-analysis";
      hash = "sha256-eUKd7qMFJURIecgnvYXCrKGhvt2P3a4wlvR+Ap81bcQ=";
    }
    {
      component = "asm-commons";
      hash = "sha256-51cHAUWrBMfGh0BCkzt9hgBFa1/bzy0CKmzQqG5aRKE=";
    }
    {
      component = "asm-util";
      hash = "sha256-59txW4vER1HZml8MAsghmq41WSFGKhasynJ2YzjBQoc=";
    }
  ];
  asmArchives =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = ["https://repo.maven.apache.org/maven2/org/ow2/asm/${archive.component}/9.6/${archive.component}-9.6-sources.jar"];
            inherit (archive) hash;
          };
        }
    )
    asmSources;
  jsr305Source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2-sources.jar"];
    hash = "sha256-HJ6F4nLQcIxqWR3HSCjHFgMFO0jMda6DzOVpEqKqBjs=";
  };
  findbugsSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/google/code/findbugs/findbugs-annotations/3.0.1/findbugs-annotations-3.0.1-sources.jar"];
    hash = "sha256-M8+8YmaF7jvNb8scTnTyus+U2eRqnUlLtZTqwIBUmSw=";
  };
  allJavaArchives = [jsr305Source findbugsSource] ++ builtins.map (archive: archive.src) asmArchives;
  archiveArguments = builtins.concatStringsSep " " (builtins.map toString allJavaArchives);
  unpackAsm = builtins.concatStringsSep "\n" (builtins.map (archive: ''
      unzip -q -o ${archive.src} -d shaded-asm-source
    '')
    asmArchives);
in
  mkDerivation {
    pname = "bazel-byte-buddy-1_14";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      legacyJdk
      bazelJna
      bazelMavenBootstrap
      buildPackages.unzip
      buildPackages.findutils
      buildPackages.python3
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - "$src" ${archiveArguments} <<'PY'
          from pathlib import Path
          import sys
          from zipfile import ZipFile

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )

          def check(name, data):
              if Path(name).suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in Byte Buddy source: {name}")
              if data[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in Byte Buddy source: {name}")

          for path in Path(sys.argv[1]).rglob("*"):
              if path.is_file():
                  check(str(path), path.read_bytes())
          for archive_path in sys.argv[2:]:
              with ZipFile(archive_path) as archive:
                  for member in archive.infolist():
                      if not member.is_dir():
                          check(member.filename, archive.read(member))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p jsr305-source findbugs-source shaded-asm-source \
            jsr305-classes findbugs-classes shaded-asm-classes \
            core-source core-classes agent-classes
          unzip -q ${jsr305Source} -d jsr305-source
          unzip -q ${findbugsSource} -d findbugs-source
          ${unpackAsm}

          find jsr305-source -type f -name '*.java' -print > jsr305-sources
          find findbugs-source -type f -name '*.java' -print > findbugs-sources
          ${legacyJdk}/bin/javac -source 6 -target 6 -encoding UTF-8 -proc:none \
            -d jsr305-classes @jsr305-sources
          ${legacyJdk}/bin/javac -source 6 -target 6 -encoding UTF-8 -proc:none \
            -cp jsr305-classes -d findbugs-classes @findbugs-sources

          find shaded-asm-source -type f -name '*.java' \
            ! -name module-info.java -print > asm-sources
          while IFS= read -r sourceFile; do
            sed -i 's/org\.objectweb\.asm/net.bytebuddy.jar.asm/g' "$sourceFile"
          done < asm-sources
          ${buildJdk}/bin/javac --release 8 -encoding UTF-8 -proc:none \
            -d shaded-asm-classes @asm-sources

          cp -a "$src/byte-buddy-dep/src/main/java/." core-source/
          find core-source -type f -name '*.java' -print > core-sources
          while IFS= read -r sourceFile; do
            sed -i 's/org\.objectweb\.asm/net.bytebuddy.jar.asm/g' "$sourceFile"
          done < core-sources
          jnaClasspath="${bazelJna}/share/java/jna-5.3.1.jar:${bazelJna}/share/java/jna-platform-5.3.1.jar"
          sourceClasspath="shaded-asm-classes:findbugs-classes:jsr305-classes:$jnaClasspath"
          ${buildJdk}/bin/javac --release 8 -encoding UTF-8 -proc:none \
            -cp "$sourceClasspath" -d core-classes @core-sources

          # Upstream checked in these advice classes at Java 6 bytecode level.
          # Compile their matching Java sources with the AOS-built JDK 8.
          find "$src/byte-buddy-dep/src/main/java-6" -type f -name '*.java' \
            -print > advice-sources
          test "$(wc -l < advice-sources)" -eq 9
          ${legacyJdk}/bin/javac -source 6 -target 6 -encoding UTF-8 -proc:none \
            -cp "core-classes:shaded-asm-classes:findbugs-classes:jsr305-classes" \
            -d core-classes @advice-sources

          find "$src/byte-buddy-agent/src/main/java" -type f -name '*.java' \
            -print > agent-sources
          ${buildJdk}/bin/javac --release 8 -encoding UTF-8 -proc:none \
            -cp "findbugs-classes:jsr305-classes:$jnaClasspath" \
            -d agent-classes @agent-sources

          ${buildJdk}/bin/jar --create --file byte-buddy.jar --no-manifest \
            --date=1980-01-01T00:00:02Z -C core-classes . -C shaded-asm-classes .
          cat > agent-manifest <<'EOF'
          Manifest-Version: 1.0
          Premain-Class: net.bytebuddy.agent.Installer
          Agent-Class: net.bytebuddy.agent.Installer
          Can-Redefine-Classes: true
          Can-Retransform-Classes: true

          EOF
          ${buildJdk}/bin/jar --create --file byte-buddy-agent.jar \
            --manifest agent-manifest --date=1980-01-01T00:00:02Z \
            -C agent-classes .

          cat > ByteBuddySmoke.java <<'JAVA'
          import net.bytebuddy.ByteBuddy;
          import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
          import net.bytebuddy.implementation.FixedValue;

          public class ByteBuddySmoke {
              public static void main(String[] arguments) throws Exception {
                  Class<?> generated = new ByteBuddy()
                      .subclass(Object.class)
                      .name("aos.bytebuddy.Generated")
                      .defineMethod("value", String.class, 1)
                      .intercept(FixedValue.value("source-built"))
                      .make()
                      .load(ByteBuddySmoke.class.getClassLoader(), ClassLoadingStrategy.Default.WRAPPER)
                      .getLoaded();
                  Object instance = generated.getDeclaredConstructor().newInstance();
                  if (!"source-built".equals(generated.getMethod("value").invoke(instance))) {
                      throw new AssertionError("Byte Buddy generated the wrong method value");
                  }
              }
          }
          JAVA
          ${buildJdk}/bin/javac -cp byte-buddy.jar ByteBuddySmoke.java
          ${buildJdk}/bin/java -cp ".:byte-buddy.jar" ByteBuddySmoke
          ${buildJdk}/bin/java -javaagent:byte-buddy-agent.jar -version
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 byte-buddy.jar \
            "$out/maven/net/bytebuddy/byte-buddy/${version}/byte-buddy-${version}.jar"
          install -Dm644 byte-buddy-agent.jar \
            "$out/maven/net/bytebuddy/byte-buddy-agent/${version}/byte-buddy-agent-${version}.jar"
          install -Dm644 "$src/LICENSE" "$out/share/licenses/byte-buddy/LICENSE"
        '';
      }
    ];
  }
