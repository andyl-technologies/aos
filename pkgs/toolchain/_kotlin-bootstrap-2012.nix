##! Second source-built Kotlin compiler stage, using the 2011 Java compiler seed.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2012-03-31";
  buildJdk = buildPackages.openjdk-8;
  seed = import ./_kotlin-bootstrap-2011.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  gitInputs = {
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
  };

  kotlinSource = fetchgit ({
      url = "https://github.com/JetBrains/kotlin.git";
      rev = "0cb26b056696df290328a11d08e05469b2198171";
      name = "kotlin-2012-java-compiler-source-only";
      hash = "sha256-UhyKX3qhTZt9rVxdsx1dj3ITxQaTEHFZDsovylhIZTQ=";
      sparsePatterns = [
        "/compiler/backend/src/"
        "/compiler/cli/src/"
        "/compiler/frontend.java/src/"
        "/compiler/frontend/src/"
        "/compiler/jet.as.java.psi/src/"
        "/compiler/util/src/"
        "/libraries/stdlib/src/"
        "/runtime/src/"
        "/LICENSE*"
        "!*.jar"
        "!*.class"
        "!*.so"
        "!*.dylib"
        "!*.dll"
        "!*.exe"
        "!*.bin"
        "!*.wasm"
        "!*.zip"
        "!*.gz"
      ];
    }
    // gitInputs);

  ideaSource = fetchgit ({
      url = "https://github.com/JetBrains/intellij-community.git";
      rev = "234fa81ae164acc4d2df1e946b6e6c2a515c5452";
      name = "intellij-2012-kotlin-compiler-source-only";
      hash = "sha256-yZ+pB560mGofaHOBZY3ckCwItbqXTLLiTldPmsjhqIk=";
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
        "!*.dylib"
        "!*.dll"
        "!*.exe"
        "!*.bin"
        "!*.wasm"
        "!*.zip"
        "!*.gz"
      ];
    }
    // gitInputs);

  injectSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/javax/inject/javax.inject/1/javax.inject-1-sources.jar"];
    hash = "sha256-xLh+4pEcE5w9r0mKeBln8esudbwahSmi57MooV0OQz4=";
  };
  annotationSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/javax/annotation/javax.annotation-api/1.3.2/javax.annotation-api-1.3.2-sources.jar"];
    hash = "sha256-Eolx5S4NhKZuO24EnauK17LFi34a03+i3r09QMKUe5U=";
  };
in
  mkDerivation {
    pname = "kotlin-bootstrap-java";
    inherit version;
    src = kotlinSource;

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.findutils
      buildPackages.coreutils
      seed
      ideaSource
    ];
    runtimeDeps = [buildJdk seed];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" kotlin
          cp -R ${ideaSource} idea
          chmod -R u+w kotlin idea
          mkdir -p sources classes

          python3 - kotlin idea <<'PY'
          from pathlib import Path
          import sys

          compiled_suffixes = {
              ".bin", ".class", ".dll", ".dylib", ".exe", ".jar", ".so", ".wasm",
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

          python3 - ${injectSource} ${annotationSource} <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          for name, archive_path in zip(("inject", "annotation"), sys.argv[1:]):
              destination = Path("sources") / name
              with ZipFile(archive_path) as archive:
                  for member in archive.infolist():
                      path = PurePosixPath(member.filename)
                      kind = stat.S_IFMT(member.external_attr >> 16)
                      if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                          raise SystemExit(f"Unsafe source archive member: {path}")
                      if member.is_dir():
                          continue
                      if path.suffix in {".class", ".jar", ".so", ".dll", ".dylib", ".exe", ".wasm"}:
                          raise SystemExit(f"Compiled source archive member: {path}")
                      if path.suffix != ".java":
                          continue
                      target = destination.joinpath(*path.parts)
                      target.parent.mkdir(parents=True, exist_ok=True)
                      target.write_bytes(archive.read(member))

          java_element_finder = Path(
              "kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/JavaElementFinder.java"
          )
          # The 2011 headless IntelliJ seed has no virtual file manager service.
          original = "VirtualFileManager.getInstance().addVirtualFileListener(new VirtualFileListener() {"
          replacement = (
              "VirtualFileManager fileManager = VirtualFileManager.getInstance();\n"
              "        if (fileManager != null) fileManager.addVirtualFileListener(new VirtualFileListener() {"
          )
          source = java_element_finder.read_text()
          if source.count(original) != 1:
              raise SystemExit("Kotlin file manager compatibility patch did not match")
          java_element_finder.write_text(source.replace(original, replacement))

          virtual_file = Path("idea/platform/core-api/src/com/intellij/openapi/vfs/VirtualFile.java")
          # The mixed bootstrap classpath can return empty child entries.
          original = "if (child.nameEquals(name)) {"
          replacement = "if (child != null && child.nameEquals(name)) {"
          source = virtual_file.read_text()
          if source.count(original) != 1:
              raise SystemExit("IntelliJ VFS compatibility patch did not match")
          virtual_file.write_text(source.replace(original, replacement))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH=${buildJdk}/bin:$PATH
          seedRoot=${seed}/share/kotlin-bootstrap
          seedClasspath="$seedRoot/dist/classes/runtime"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            seedClasspath="$seedClasspath:$seedRoot/deps/$dependency"
          done

          find sources/inject sources/annotation -name '*.java' | LC_ALL=C sort > api-files
          mkdir -p classes/api
          javac -proc:none -d classes/api @api-files

          cat > idea-files <<'FILES'
          idea/platform/util/src/com/intellij/util/containers/LinkedMultiMap.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/light/AbstractLightClass.java
          idea/platform/util/src/com/intellij/util/CollectionQuery.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/compiled/ClsCustomNavigationPolicy.java
          idea/java/java-psi-impl/src/com/intellij/core/CoreJavaFileManager.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/compiled/ClsClassImpl.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/VirtualFile.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/local/CoreLocalVirtualFile.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/local/CoreLocalFileSystem.java
          FILES

          mkdir -p classes/idea
          javac -proc:none -cp "classes/api:$seedClasspath" \
            -d classes/idea @idea-files

          kotlinRoots=
          for root in \
            kotlin/compiler/frontend/src \
            kotlin/compiler/frontend.java/src \
            kotlin/compiler/backend/src \
            kotlin/compiler/cli/src \
            kotlin/compiler/util/src \
            kotlin/compiler/jet.as.java.psi/src \
            kotlin/runtime/src; do
            find "$root" -name '*.java' | LC_ALL=C sort >> kotlin-files
            kotlinRoots="$root''${kotlinRoots:+:$kotlinRoots}"
          done

          mkdir -p classes/kotlin
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp "classes/idea:classes/api:$seedClasspath" \
            -sourcepath "$kotlinRoots" \
            -d classes/kotlin @kotlin-files
          cp -R kotlin/compiler/frontend/src/jet/. classes/kotlin/jet/
        '';
      }
      {
        name = "check";
        script = ''
          cat > smoke.kt <<'KOTLIN'
          fun answer(): Int = 40 + 2
          KOTLIN

          mkdir -p smoke-classes
          java -cp "classes/kotlin:classes/idea:classes/api:$seedClasspath" \
            org.jetbrains.jet.cli.KotlinCompiler \
            -src "$PWD/smoke.kt" -output "$PWD/smoke-classes" \
            > smoke.log 2>&1
          test -f smoke-classes/namespace.class
          python3 - <<'PY'
          from pathlib import Path

          log = Path("smoke.log").read_text()
          if "ERROR:" in log or "INTERNAL_ERROR" in log:
              raise SystemExit(log)
          PY

          cat > KotlinStage2Check.java <<'JAVA'
          public final class KotlinStage2Check {
              public static void main(String[] args) {
                  if (namespace.answer() != 42) {
                      throw new AssertionError("Kotlin compiler produced the wrong result");
                  }
              }
          }
          JAVA
          javac -proc:none -cp smoke-classes -d smoke-classes KotlinStage2Check.java
          java -cp smoke-classes KotlinStage2Check
        '';
      }
      {
        name = "install";
        script = ''
          root="$out/share/kotlin-bootstrap"
          mkdir -p "$out/bin" "$root"
          cp -R classes/api classes/idea classes/kotlin "$root/"

          cat > "$out/bin/kotlinc-bootstrap" <<'SH'
          #!${buildPackages.bash}/bin/bash
          set -eu
          export JAVA_HOME=${buildJdk}
          root="${placeholder "out"}/share/kotlin-bootstrap"
          seedRoot=${seed}/share/kotlin-bootstrap
          classpath="$root/kotlin:$root/idea:$root/api:$seedRoot/dist/classes/runtime"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done
          exec ${buildJdk}/bin/java -cp "$classpath" \
            org.jetbrains.jet.cli.KotlinCompiler "$@"
          SH
          chmod +x "$out/bin/kotlinc-bootstrap"
        '';
      }
    ];

    meta = {
      description = "2012 Kotlin compiler stage built from the Java compiler seed";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "mixed";
    };
  }
