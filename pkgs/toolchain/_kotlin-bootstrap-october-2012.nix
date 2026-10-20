##! October 2012 Kotlin JVM compiler stage built from Java sources.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2012-10-26";
  buildJdk = buildPackages.openjdk-8;
  seed = import ./_kotlin-bootstrap-2011.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  marchStage = import ./_kotlin-bootstrap-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  juneStage = import ./_kotlin-bootstrap-june-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  octoberApi = import ./_kotlin-idea-api-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  ideaCore = import ./_kotlin-idea-core-2012.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  source = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "4955ce5caa9ad28d9df363767d247f33c2517ca8";
    name = "kotlin-2012-october-java-compiler-source-only";
    hash = "sha256-Ayo5WDNXD738IZmQ6HcOSqOfCznMIBXr8La8Cr59Vjs=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/js/js.translator/src/"
      "/js/js.libraries/src/"
      "/compiler/backend/src/"
      "/compiler/cli/src/"
      "/compiler/cli/cli-common/src/"
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
  };
in
  mkDerivation {
    pname = "kotlin-bootstrap-java";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.findutils
      buildPackages.coreutils
      seed
      marchStage
      juneStage
      octoberApi
      ideaCore
    ];
    runtimeDeps = [buildJdk seed marchStage juneStage octoberApi ideaCore];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" kotlin
          chmod -R u+w kotlin

          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".bin", ".class", ".dll", ".dylib", ".exe", ".jar", ".so", ".wasm",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("feedface"),
              bytes.fromhex("feedfacf"), bytes.fromhex("4d5a"),
          )
          for path in Path("kotlin").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled Kotlin input: {path}")
              if path.read_bytes().startswith(compiled_signatures):
                  raise SystemExit(f"Compiled Kotlin input: {path}")

          environment = Path(
              "kotlin/compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/JetCoreEnvironment.java"
          )
          source = environment.read_text()
          replacements = {
              # The May environment already registers its Java file manager.
              "        project.registerService(CoreJavaFileManager.class, (CoreJavaFileManager) ServiceManager.getService(project, JavaFileManager.class));\n":
                  "",
              "projectEnvironment.addJarToClassPath(path);":
                  "projectEnvironment.addToClasspath(path);",
              "projectEnvironment.addSourcesToClasspath(root);":
                  "projectEnvironment.addToClasspath(path);",
          }
          for original, replacement in replacements.items():
              if source.count(original) != 1:
                  raise SystemExit("Kotlin headless environment compatibility patch did not match")
              source = source.replace(original, replacement)
          environment.write_text(source)

          resolver = Path(
              "kotlin/compiler/frontend.java/src/org/jetbrains/jet/lang/resolve/java/resolver/JavaClassResolver.java"
          )
          source = resolver.read_text()
          original = 'StringUtil.join(correctedSegments, ".")'
          replacement = (
              "StringUtil.join(correctedSegments, new com.intellij.util.Function<Name, String>() {\n"
              "            public String fun(Name value) { return value.toString(); }\n"
              '        }, ".")'
          )
          if source.count(original) != 1:
              raise SystemExit("Kotlin name joining compatibility patch did not match")
          resolver.write_text(source.replace(original, replacement))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH=${buildJdk}/bin:$PATH
          seedRoot=${seed}/share/kotlin-bootstrap
          marchRoot=${marchStage}/share/kotlin-bootstrap
          juneRoot=${juneStage}/share/kotlin-bootstrap
          apiRoot=${octoberApi}/share/kotlin-idea-api
          coreRoot=${ideaCore}/share/kotlin-idea-core

          # Exclude older Kotlin compiler classes while retaining seed IntelliJ APIs.
          mkdir -p classes/seed/org/jetbrains classes/kotlin
          ln -s "$seedRoot/dist/classes/runtime/com" classes/seed/com
          ln -s "$seedRoot/dist/classes/runtime/org/jetbrains/annotations" \
            classes/seed/org/jetbrains/annotations
          ln -s "$seedRoot/dist/classes/runtime/org/jdom" classes/seed/org/jdom

          classpath="$coreRoot/classes:$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:classes/seed"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done

          sourcepath=
          for root in \
            kotlin/compiler/frontend/src \
            kotlin/compiler/frontend.java/src \
            kotlin/compiler/backend/src \
            kotlin/compiler/cli/src \
            kotlin/compiler/util/src \
            kotlin/compiler/jet.as.java.psi/src \
            kotlin/runtime/src; do
            find "$root" -name '*.java' ! -path '*/cli/js/*' \
              | LC_ALL=C sort >> kotlin-files
            sourcepath="$root''${sourcepath:+:$sourcepath}"
          done

          # This intermediate stage supplies the JVM compiler. Its JavaScript
          # frontend is built later with the separate source-built Dart AST.
          javac -encoding UTF-8 -source 7 -target 7 -proc:none -Xprefer:source \
            -cp "$classpath" -sourcepath "$sourcepath" \
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
          java -cp "classes/kotlin:$classpath" \
            org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdkAnnotations \
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
          cp -R classes/kotlin classes/seed "$root/"

          cat > "$out/bin/kotlinc-bootstrap" <<'SH'
          #!${buildPackages.bash}/bin/bash
          set -eu
          root="${placeholder "out"}/share/kotlin-bootstrap"
          seedRoot=${seed}/share/kotlin-bootstrap
          marchRoot=${marchStage}/share/kotlin-bootstrap
          juneRoot=${juneStage}/share/kotlin-bootstrap
          apiRoot=${octoberApi}/share/kotlin-idea-api
          coreRoot=${ideaCore}/share/kotlin-idea-core
          classpath="$root/kotlin:$coreRoot/classes:$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:$root/seed"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done
          exec ${buildJdk}/bin/java -cp "$classpath" \
            org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdkAnnotations "$@"
          SH
          chmod +x "$out/bin/kotlinc-bootstrap"
        '';
      }
    ];

    meta = {
      description = "October 2012 Kotlin JVM compiler built from Java sources";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "mixed";
    };
  }
