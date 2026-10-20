##! June 2012 Kotlin compiler stage built from Java sources and the earlier seed.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2012-06-30";
  buildJdk = buildPackages.openjdk-8;
  seed = import ./_kotlin-bootstrap-2011.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  previousStage = import ./_kotlin-bootstrap-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  gitInputs = {
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
  };

  kotlinSource = fetchgit ({
      url = "https://github.com/JetBrains/kotlin.git";
      rev = "0da54aac1c5a004e408c4da83f680e7b29f5073b";
      name = "kotlin-2012-june-java-compiler-source-only";
      hash = "sha256-P3YXey5EM9JkJMtgMq3OoI7FT4Yfk1DQMMIPUNFbXRc=";
      sparsePatterns = [
        "/compiler/backend/src/"
        "/compiler/cli/src/"
        "/compiler/frontend.java/src/"
        "/compiler/frontend/src/"
        "/compiler/jet.as.java.psi/src/"
        "/compiler/util/src/"
        "/runtime/src/"
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

  javaSources = {
    hawtjni = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/fusesource/hawtjni/hawtjni-runtime/1.7/hawtjni-runtime-1.7-sources.jar"];
      hash = "sha256-qzEJzkfBX+uE2d/mFz/bGJ9K70TYyN9s3OvdA4KELsQ=";
    };
    jansiNative = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/fusesource/jansi/jansi-native/1.5/jansi-native-1.5-sources.jar"];
      hash = "sha256-2arq/LvQ6xTaMllkZpaEWfgm9DzbOvWSgWCG0dErryg=";
    };
    jansi = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/fusesource/jansi/jansi/1.10/jansi-1.10-sources.jar"];
      hash = "sha256-3NeScygsm4EIVXkWiQvXgSUsKdzCf+dLgHD58z+VezA=";
    };
    jline = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/jline/jline/2.10/jline-2.10-sources.jar"];
      hash = "sha256-DMI70ncM4thoeumYg76jfmQ4SMM3uWtq7vRojlRHZ74=";
    };
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
      previousStage
      ideaSource
    ];
    runtimeDeps = [buildJdk seed previousStage];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" kotlin
          chmod -R u+w kotlin
          mkdir -p sources classes

          python3 - kotlin ${ideaSource} <<'PY'
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

          python3 - \
            ${javaSources.hawtjni} \
            ${javaSources.jansiNative} \
            ${javaSources.jansi} \
            ${javaSources.jline} <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          for name, archive_path in zip(
              ("hawtjni", "jansi-native", "jansi", "jline"), sys.argv[1:]
          ):
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
          # The 2011 seed does not register a virtual file manager service.
          original = "VirtualFileManager.getInstance().addVirtualFileListener(new VirtualFileListener() {"
          replacement = (
              "VirtualFileManager fileManager = VirtualFileManager.getInstance();\n"
              "        if (fileManager != null) fileManager.addVirtualFileListener(new VirtualFileListener() {"
          )
          source = java_element_finder.read_text()
          if source.count(original) != 1:
              raise SystemExit("Kotlin file manager compatibility patch did not match")
          java_element_finder.write_text(source.replace(original, replacement))

          path_util = Path("kotlin/compiler/util/src/org/jetbrains/jet/utils/PathUtil.java")
          source = path_util.read_text()
          source = source.replace(
              "import com.intellij.openapi.vfs.VirtualFileManager;",
              "import com.intellij.openapi.vfs.VirtualFileManager;\n"
              "import com.intellij.openapi.vfs.local.CoreLocalFileSystem;\n"
              "import com.intellij.openapi.vfs.impl.jar.CoreJarFileSystem;",
          )
          patches = {
              "return VirtualFileManager.getInstance()\n"
              "                        .findFileByUrl(\"file://\" + FileUtil.toSystemIndependentName(file.getAbsolutePath()));":
                  "VirtualFileManager manager = VirtualFileManager.getInstance();\n"
                  "                return manager != null\n"
                  "                        ? manager.findFileByUrl(\"file://\" + FileUtil.toSystemIndependentName(file.getAbsolutePath()))\n"
                  "                        : new CoreLocalFileSystem().findFileByPath(file.getAbsolutePath());",
              "return VirtualFileManager.getInstance().findFileByUrl(\"jar://\" + FileUtil.toSystemIndependentName(file.getAbsolutePath()) + \"!/\");":
                  "VirtualFileManager manager = VirtualFileManager.getInstance();\n"
                  "                return manager != null\n"
                  "                        ? manager.findFileByUrl(\"jar://\" + FileUtil.toSystemIndependentName(file.getAbsolutePath()) + \"!/\")\n"
                  "                        : new CoreJarFileSystem().findFileByPath(file.getAbsolutePath() + \"!/\");",
          }
          for original, replacement in patches.items():
              if source.count(original) != 1:
                  raise SystemExit("Kotlin path compatibility patch did not match")
              source = source.replace(original, replacement)
          path_util.write_text(source)

          facade = Path(
              "kotlin/compiler/frontend.java/src/org/jetbrains/jet/lang/resolve/java/JavaPsiFacadeKotlinHacks.java"
          )
          source = facade.read_text()
          source = source.replace(
              "import com.intellij.psi.PsiElementFinder;",
              "import com.intellij.psi.PsiElementFinder;\nimport com.intellij.psi.JavaPsiFacade;",
          ).replace(
              "import java.util.List;",
              "import java.util.List;\nimport java.util.Collection;\nimport java.util.Collections;",
          )
          original = 'throw new IllegalStateException("JavaFileManager component is not found in project");'
          replacement = "\n".join((
              "// The 2011 seed exposes its file manager through JavaPsiFacade.",
              "        final JavaPsiFacade javaFacade = JavaPsiFacade.getInstance(project);",
              "        return new JavaFileManager() {",
              "            public PsiPackage findPackage(String name) {",
              "                return javaFacade.findPackage(name);",
              "            }",
              "",
              "            public PsiClass findClass(String name, GlobalSearchScope scope) {",
              "                return javaFacade.findClass(name, scope);",
              "            }",
              "",
              "            public PsiClass[] findClasses(String name, GlobalSearchScope scope) {",
              "                return javaFacade.findClasses(name, scope);",
              "            }",
              "",
              "            public Collection<String> getNonTrivialPackagePrefixes() {",
              "                return Collections.emptyList();",
              "            }",
              "",
              "            public void initialize() {",
              "            }",
              "        };",
          ))
          if source.count(original) != 1:
              raise SystemExit("Kotlin Java facade compatibility patch did not match")
          facade.write_text(source.replace(original, replacement))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH=${buildJdk}/bin:$PATH
          seedRoot=${seed}/share/kotlin-bootstrap
          previousRoot=${previousStage}/share/kotlin-bootstrap

          # Keep 2011 IntelliJ APIs while excluding its old Kotlin compiler classes.
          mkdir -p classes/seed/org/jetbrains classes/idea classes/java-deps classes/kotlin
          ln -s "$seedRoot/dist/classes/runtime/com" classes/seed/com
          ln -s "$seedRoot/dist/classes/runtime/org/jetbrains/annotations" \
            classes/seed/org/jetbrains/annotations

          seedClasspath=classes/seed
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            seedClasspath="$seedClasspath:$seedRoot/deps/$dependency"
          done
          ideaClasspath="classes/idea:$previousRoot/idea:$previousRoot/api:$seedClasspath"

          cat > idea-files <<'FILES'
          ${ideaSource}/platform/util/src/com/intellij/util/PlusMinus.java
          ${ideaSource}/platform/util/src/com/intellij/util/containers/ComparatorUtil.java
          ${ideaSource}/platform/core-api/src/com/intellij/psi/tree/ILazyParseableElementType.java
          FILES
          javac -proc:none -cp "$ideaClasspath" -d classes/idea @idea-files

          find sources/hawtjni sources/jansi-native sources/jansi -name '*.java' \
            | LC_ALL=C sort > jansi-files
          javac -encoding UTF-8 -proc:none -d classes/java-deps @jansi-files
          find sources/jline -name '*.java' | LC_ALL=C sort > jline-files
          javac -encoding UTF-8 -proc:none -cp classes/java-deps \
            -d classes/java-deps @jline-files

          kotlinRoots=
          for root in \
            kotlin/compiler/frontend/src \
            kotlin/compiler/frontend.java/src \
            kotlin/compiler/backend/src \
            kotlin/compiler/cli/src \
            kotlin/compiler/util/src \
            kotlin/compiler/jet.as.java.psi/src \
            kotlin/runtime/src; do
            # This intermediate stage supplies the JVM compiler. The JS frontend
            # enters the later stage with its separate Dart AST dependency.
            find "$root" -name '*.java' ! -path '*/cli/js/*' \
              | LC_ALL=C sort >> kotlin-files
            kotlinRoots="$root''${kotlinRoots:+:$kotlinRoots}"
          done

          javac -encoding UTF-8 -source 7 -target 7 -proc:none -Xprefer:source \
            -cp "classes/java-deps:$ideaClasspath:$seedRoot/dist/classes/runtime" \
            -sourcepath "$kotlinRoots" -d classes/kotlin @kotlin-files
          cp -R kotlin/compiler/frontend/src/jet/. classes/kotlin/jet/
        '';
      }
      {
        name = "check";
        script = ''
          cat > smoke.kt <<'KOTLIN'
          fun answer(): Int = 40 + 2
          KOTLIN

          classpath="classes/kotlin:classes/java-deps:$ideaClasspath:$seedRoot/dist/classes/runtime"
          mkdir -p smoke-classes
          java -cp "$classpath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -jdkHeaders "$seedRoot/dist/classes/runtime" \
            -stdlib "$seedRoot/dist/classes/runtime" \
            -src "$PWD/smoke.kt" -output "$PWD/smoke-classes" \
            > smoke.log 2>&1
          test -f smoke-classes/namespace.class

          cat > KotlinStageCheck.java <<'JAVA'
          public final class KotlinStageCheck {
              public static void main(String[] args) {
                  if (namespace.answer() != 42) {
                      throw new AssertionError("Kotlin compiler produced the wrong result");
                  }
              }
          }
          JAVA
          javac -proc:none -cp smoke-classes -d smoke-classes KotlinStageCheck.java
          java -cp smoke-classes KotlinStageCheck
        '';
      }
      {
        name = "install";
        script = ''
          root="$out/share/kotlin-bootstrap"
          mkdir -p "$out/bin" "$root"
          cp -R classes/idea classes/java-deps classes/kotlin "$root/"

          cat > "$out/bin/kotlinc-bootstrap" <<'SH'
          #!${buildPackages.bash}/bin/bash
          set -eu
          root="${placeholder "out"}/share/kotlin-bootstrap"
          seedRoot=${seed}/share/kotlin-bootstrap
          previousRoot=${previousStage}/share/kotlin-bootstrap
          classpath="$root/kotlin:$root/java-deps:$root/idea:$previousRoot/idea:$previousRoot/api:$seedRoot/dist/classes/runtime"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done
          exec ${buildJdk}/bin/java -cp "$classpath" \
            org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -jdkHeaders "$seedRoot/dist/classes/runtime" \
            -stdlib "$seedRoot/dist/classes/runtime" "$@"
          SH
          chmod +x "$out/bin/kotlinc-bootstrap"
        '';
      }
    ];

    meta = {
      description = "June 2012 Kotlin compiler stage built from Java sources";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "mixed";
    };
  }
