##! Java-only Kotlin compiler seed assembled entirely from source.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2011-11-30";
  buildJdk = buildPackages.openjdk-8;
  reproducibleJdk = buildPackages.openjdk-21;

  gitInputs = {
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
  };

  kotlinSource = fetchgit ({
      url = "https://github.com/JetBrains/kotlin.git";
      rev = "957b2173d98d0c39500a627ed064b6af95084758";
      name = "kotlin-2011-java-compiler-source-only";
      hash = "sha256-/wZskLV5WrecqyV08BMPEzGZ5C7qKW4fzuQExwWLxfk=";
      sparsePatterns = [
        "/compiler/frontend/src/"
        "/compiler/frontend.java/src/"
        "/compiler/backend/src/"
        "/compiler/cli/src/"
        "/stdlib/src/"
        "/stdlib/ktSrc/"
        "!*.jar"
        "!*.class"
        "!*.so"
        "!*.dll"
        "!*.dylib"
        "!*.exe"
      ];
    }
    // gitInputs);

  ideaSource = fetchgit ({
      url = "https://github.com/JetBrains/intellij-community.git";
      rev = "6d48a106d41b24d826945d55ae188caa002a843a";
      name = "intellij-2011-kotlin-compiler-source-only";
      hash = "sha256-oTOT/ecB6842CDxxhOHekcRkK2gpXD29xWdVQx+lZDQ=";
      sparsePatterns = [
        "/platform/util/src/"
        "/platform/annotations/src/"
        "/platform/extensions/src/"
        "/platform/boot/src/"
        "/platform/core-api/src/"
        "/platform/core-impl/src/"
        "/platform/platform-api/src/"
        "/platform/platform-impl/src/"
        "/platform/lang-api/src/"
        "/platform/lang-impl/src/"
        "/java/java-psi-api/src/"
        "/java/java-psi-impl/src/"
        "/java/java-impl/src/"
        "/java/openapi/src/"
        "!*.jar"
        "!*.class"
        "!*.so"
        "!*.dll"
        "!*.dylib"
        "!*.exe"
      ];
    }
    // gitInputs);

  asmSource = fetchgit ({
      url = "https://gitlab.ow2.org/asm/asm.git";
      rev = "d6f33999569493c18f04686facf8e91484db7ee6";
      name = "asm-3.3.1-source-only";
      hash = "sha256-8DcRUSIboEjgjGT7+EKDY5jt58k0px66U9TvLDayz7g=";
      sparsePatterns = [
        "/src/org/objectweb/asm/"
        "/LICENSE.txt"
        "!*.jar"
        "!*.class"
        "!*.gz"
      ];
    }
    // gitInputs);

  sourceArchives = {
    jsr305 = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2-sources.jar"];
      hash = "sha256-HJ6F4nLQcIxqWR3HSCjHFgMFO0jMda6DzOVpEqKqBjs=";
    };
    guava = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/google/guava/guava/r09/guava-r09-sources.jar"];
      hash = "sha256-Plpy2GNtVXrqV8ome6DWvGp+dtc3iJ7VzoDIVykIgDo=";
    };
    trove = fetchurl {
      urls = ["https://raw.githubusercontent.com/JetBrains/intellij-community/6d48a106d41b24d826945d55ae188caa002a843a/lib/src/trove4j_src.jar"];
      hash = "sha256-NqcgsrER/OjmERcyR/dakgn9KnHfZvmcakfWP7hCWOQ=";
    };
    pico = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/picocontainer/picocontainer/1.3/picocontainer-1.3-sources.jar"];
      hash = "sha256-e49UVlpexiO6Ch6vWH/inwfrvlwz2O4dMp9ke3vhrNQ=";
    };
    jna = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/net/java/dev/jna/jna/3.2.7/jna-3.2.7-sources.jar"];
      hash = "sha256-5mEbKBTVgJyhJ8Z19bZ700KnjzNwggxXY5GwgJTpG+o=";
    };
    cli = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/github/spullara/cli-parser/cli-parser/1.1.5/cli-parser-1.1.5-sources.jar"];
      hash = "sha256-x/ObgE5z/f2u7Rfo0j3rxBZv2f/2VKYepQyldJfCMW0=";
    };
    jdom = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/jdom/jdom/1.1.2/jdom-1.1.2-sources.jar"];
      hash = "sha256-DNUffX+dNt03mo625klDTcsLsQVHHwpPxbYMP2UdDKY=";
    };
    log4j = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/log4j/log4j/1.2.16/log4j-1.2.16-sources.jar"];
      hash = "sha256-Pe2/Fxl+7BoWodkzP2x2Wonj+jIL5SoNN+At8e0Vlg8=";
    };
  };

  unpackArchives = builtins.concatStringsSep "\n" (
    builtins.map
    (name: ''
      python3 - ${sourceArchives.${name}} "$PWD/sources/${name}" <<'PY'
      from pathlib import Path, PurePosixPath
      from zipfile import ZipFile
      import stat
      import sys

      destination = Path(sys.argv[2])
      with ZipFile(sys.argv[1]) as archive:
          for member in archive.infolist():
              path = PurePosixPath(member.filename)
              kind = stat.S_IFMT(member.external_attr >> 16)
              if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                  raise SystemExit(f"Unsafe source archive member: {path}")
              if member.is_dir():
                  continue
              if path.suffix in {".class", ".jar", ".so", ".dll", ".dylib", ".exe"}:
                  raise SystemExit(f"Compiled source archive member: {path}")
              if path.suffix not in {".java", ".properties"}:
                  continue
              data = archive.read(member)
              if data.startswith((
                  bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
                  bytes.fromhex("0061736d"), bytes.fromhex("4d5a"),
              )):
                  raise SystemExit(f"Compiled source archive member: {path}")
              target = destination.joinpath(*path.parts)
              target.parent.mkdir(parents=True, exist_ok=True)
              target.write_bytes(data)
      PY
    '')
    (builtins.attrNames sourceArchives)
  );
in
  mkDerivation {
    pname = "kotlin-bootstrap-java";
    inherit version;
    src = kotlinSource;

    buildDeps = [
      buildJdk
      reproducibleJdk
      buildPackages.python3
      buildPackages.findutils
      buildPackages.coreutils
      ideaSource
      asmSource
    ];
    runtimeDeps = [buildJdk];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" kotlin
          chmod -R u+w kotlin
          cp -R ${ideaSource} idea
          cp -R ${asmSource} asm
          mkdir -p sources classes
          ${unpackArchives}

          python3 - kotlin idea asm <<'PY'
          from pathlib import Path
          import sys

          compiled_suffixes = {
              ".a", ".bin", ".class", ".dll", ".dylib", ".exe", ".jar",
              ".o", ".so", ".wasm", ".zip", ".gz",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("feedface"),
              bytes.fromhex("feedfacf"), bytes.fromhex("4d5a"),
          )
          for root in map(Path, sys.argv[1:]):
              for path in root.rglob("*"):
                  if not path.is_file():
                      continue
                  if path.suffix.lower() in compiled_suffixes:
                      raise SystemExit(f"Compiled bootstrap input: {path}")
                  if path.read_bytes().startswith(compiled_signatures):
                      raise SystemExit(f"Compiled bootstrap input: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH=${buildJdk}/bin:$PATH

          find sources/jsr305 -name '*.java' | LC_ALL=C sort > jsr305-files
          mkdir -p classes/jsr305
          javac -proc:none -d classes/jsr305 @jsr305-files

          find sources/guava -name '*.java' | LC_ALL=C sort > guava-files
          mkdir -p classes/guava
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp classes/jsr305 -d classes/guava @guava-files

          find asm/src -name '*.java' | LC_ALL=C sort > asm-files
          mkdir -p classes/asm
          javac -source 7 -target 7 -proc:none \
            -d classes/asm @asm-files

          find sources/trove/src/gnu/trove -name '*.java' \
            ! -path '*/benchmark/*' | LC_ALL=C sort > trove-files
          mkdir -p classes/trove
          javac -encoding ISO-8859-1 -proc:none \
            -d classes/trove @trove-files

          find sources/pico -name '*.java' | LC_ALL=C sort > pico-files
          mkdir -p classes/pico
          javac -proc:none -d classes/pico @pico-files

          find sources/jna/com/sun/jna -name '*.java' | LC_ALL=C sort > jna-files
          mkdir -p classes/jna
          javac -encoding UTF-8 -proc:none -d classes/jna @jna-files

          find sources/cli -name '*.java' | LC_ALL=C sort > cli-files
          mkdir -p classes/cli
          javac -proc:none -d classes/cli @cli-files

          kotlin_roots=
          for root in \
            kotlin/stdlib/src \
            kotlin/compiler/frontend/src \
            kotlin/compiler/frontend.java/src \
            kotlin/compiler/backend/src \
            kotlin/compiler/cli/src; do
            find "$root" -name '*.java' | LC_ALL=C sort >> kotlin-files
            kotlin_roots="$root''${kotlin_roots:+:$kotlin_roots}"
          done

          idea_roots=$(find idea/platform idea/java -type d -name src \
            | LC_ALL=C sort | paste -sd: -)
          classpath=classes/asm:classes/trove:classes/pico:classes/guava:classes/jsr305:classes/cli:classes/jna
          sourcepath="$kotlin_roots:$idea_roots:sources/jdom:sources/log4j"
          mkdir -p kotlin/dist/classes/runtime
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp "$classpath" -sourcepath "$sourcepath" \
            -d kotlin/dist/classes/runtime @kotlin-files

          # JDK 8 emits these IDEA constant pools in unstable order.
          # Recompile them with the source-built JDK 21 at Java 8 bytecode level.
          ${reproducibleJdk}/bin/javac --release 8 -proc:none \
            -cp "kotlin/dist/classes/runtime:$classpath" \
            -d kotlin/dist/classes/runtime \
            idea/java/java-psi-impl/src/com/intellij/psi/PsiDiamondTypeImpl.java \
            idea/java/java-psi-impl/src/com/intellij/psi/impl/PsiClassImplUtil.java

          mkdir -p kotlin/dist/classes/runtime/messages \
            kotlin/dist/classes/runtime/jet
          cp idea/java/java-psi-api/src/messages/JavaCoreBundle.properties \
            kotlin/dist/classes/runtime/messages/
          cp kotlin/compiler/frontend/src/jet/Library.jet \
            kotlin/dist/classes/runtime/jet/
        '';
      }
      {
        name = "check";
        script = ''
          cat > smoke.kt <<'KOTLIN'
          fun main(args: Array<String>) {
              System.out?.println("AOS Kotlin bootstrap")
          }
          KOTLIN

          mkdir -p smoke-classes
          JAVA_HOME=${buildJdk} ${buildJdk}/bin/java \
            -cp "kotlin/dist/classes/runtime:$classpath" \
            org.jetbrains.jet.cli.KotlinCompiler \
            -src "$PWD/smoke.kt" -output "$PWD/smoke-classes" \
            > smoke.log 2>&1
          test -f smoke-classes/namespace.class
          test ! -s smoke.log
        '';
      }
      {
        name = "install";
        script = ''
          root="$out/share/kotlin-bootstrap"
          mkdir -p "$out/bin" "$root/dist/classes" "$root/stdlib" \
            "$root/deps" "$out/share/licenses/kotlin-bootstrap"
          cp -R kotlin/dist/classes/runtime "$root/dist/classes/"
          cp -R kotlin/stdlib/ktSrc "$root/stdlib/"
          for dependency in asm trove pico guava jsr305 cli jna; do
            cp -R "classes/$dependency" "$root/deps/$dependency"
          done
          cp asm/LICENSE.txt "$out/share/licenses/kotlin-bootstrap/ASM-LICENSE.txt"

          cat > "$out/bin/kotlinc-bootstrap" <<'SH'
          #!${buildPackages.bash}/bin/bash
          set -eu
          export JAVA_HOME=${buildJdk}
          root="${placeholder "out"}/share/kotlin-bootstrap"
          classpath="$root/dist/classes/runtime"
          for dependency in asm trove pico guava jsr305 cli jna; do
            classpath="$classpath:$root/deps/$dependency"
          done
          exec ${buildJdk}/bin/java -cp "$classpath" \
            org.jetbrains.jet.cli.KotlinCompiler "$@"
          SH
          chmod +x "$out/bin/kotlinc-bootstrap"
        '';
      }
    ];

    meta = {
      description = "Java-only Kotlin compiler seed built from source";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "mixed";
    };
  }
