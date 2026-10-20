##! August 2013 Kotlin JVM compiler stage with source-generated serialized builtins.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2013-08-30";
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
  protobufLite = import ./_protobuf-java-lite-2_5.nix {
    inherit mkDerivation fetchurl buildPackages;
  };
  builtinsGenerator = import ./_kotlin-builtins-generator-2013.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  source = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "440716c81713a3a14cace55e335d7bddec2c5e06";
    name = "kotlin-2013-serialized-compiler-source-only";
    hash = "sha256-gbHdMlS4Ud+fJQNA3Avl3x4gYdnt51HiTqDiB9FQQXg=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/compiler/backend/src/"
      "/compiler/cli/src/"
      "/compiler/cli/cli-common/src/"
      "/compiler/frontend.java/src/"
      "/compiler/frontend.java/serialization.java/src/"
      "/compiler/frontend/src/"
      "/compiler/frontend/serialization/src/"
      "/compiler/frontend/builtins/jet/"
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
      "!*.kotlin_class"
      "!*.kotlin_name_table"
      "!*.kotlin_class_names"
      "!*.kotlin_package"
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
      protobufLite
      builtinsGenerator
    ];
    runtimeDeps = [buildJdk seed marchStage juneStage octoberApi ideaCore protobufLite];

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
              ".kotlin_class", ".kotlin_name_table", ".kotlin_class_names", ".kotlin_package",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("feedface"),
              bytes.fromhex("feedfacf"), bytes.fromhex("4d5a"),
          )
          for path in Path("kotlin").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes or path.name.startswith(".kotlin_"):
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

          def replace(relative_path, original, replacement):
              path = Path("kotlin") / relative_path
              text = path.read_text()
              if text.count(original) != 1:
                  raise SystemExit(f"Kotlin compatibility patch did not match: {relative_path}")
              path.write_text(text.replace(original, replacement))

          replace(
              "compiler/frontend/src/org/jetbrains/jet/lang/resolve/OverrideResolver.java",
              "ContainerUtil.reverse(context.getClassesTopologicalOrder())",
              "Lists.reverse(context.getClassesTopologicalOrder())",
          )
          replace(
              "compiler/frontend/src/org/jetbrains/jet/lang/psi/JetPsiUtil.java",
              "ContainerUtil.reverse(reversedNames)",
              "Lists.reverse(reversedNames)",
          )
          replace(
              "compiler/frontend/src/org/jetbrains/jet/lang/cfg/pseudocode/PseudocodeImpl.java",
              "Queues.newArrayDeque()",
              "new ArrayDeque<Instruction>()",
          )
          replace(
              "compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/messages/OutputMessageUtil.java",
              'StringUtil.join(sourceFiles, "\\n")',
              'StringUtil.join(sourceFiles, new com.intellij.util.Function<File, String>() {\n'
              '                   public String fun(File value) { return value.toString(); }\n'
              '               }, "\\n")',
          )
          replace(
              "compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/messages/OutputMessageUtil.java",
              "Collection<File> sourceFiles = ContainerUtil.newArrayList();",
              "Collection<File> sourceFiles = new java.util.ArrayList<File>();",
          )
          replace(
              "compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/CompileEnvironmentUtil.java",
              "import com.intellij.openapi.util.io.FileUtilRt;",
              "import com.intellij.openapi.util.io.FileUtil;",
          )
          replace(
              "compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/CompileEnvironmentUtil.java",
              "FileUtilRt.getExtension(moduleDefinitionFile)",
              "FileUtil.getExtension(moduleDefinitionFile)",
          )
          replace(
              "compiler/frontend/src/org/jetbrains/jet/lang/resolve/BindingContextUtils.java",
              'StringUtil.join(overriddenDescriptors, ",\\n")',
              'com.google.common.base.Joiner.on(",\\n").join(overriddenDescriptors)',
          )
          replace(
              "compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/CompileEnvironmentUtil.java",
              'FileUtilRt.extensionEquals(e.getName(), "class")',
              'FileUtil.getExtension(e.getName()).equals("class")',
          )
          replace(
              "compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/modules/ModuleXmlParser.java",
              "import com.intellij.openapi.util.io.StreamUtil;\n",
              "",
          )
          replace(
              "compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/modules/ModuleXmlParser.java",
              "            StreamUtil.closeStream(stream);",
              "            if (stream != null) {\n"
              "                try {\n"
              "                    stream.close();\n"
              "                } catch (IOException ignored) {\n"
              "                    // Closing a parsed module file must not hide its result.\n"
              "                }\n"
              "            }",
          )
          PY

          python3 ${./_kotlin-bootstrap-serialized-patch.py}
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
          protobufRoot=${protobufLite}/share/protobuf-java-lite

          # Exclude older Kotlin compiler classes while retaining seed IntelliJ APIs.
          mkdir -p classes/seed/org/jetbrains classes/kotlin
          ln -s "$seedRoot/dist/classes/runtime/com" classes/seed/com
          ln -s "$seedRoot/dist/classes/runtime/org/jetbrains/annotations" \
            classes/seed/org/jetbrains/annotations
          ln -s "$seedRoot/dist/classes/runtime/org/jdom" classes/seed/org/jdom

          classpath="$coreRoot/classes:$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:$protobufRoot/classes:classes/seed"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done

          sourcepath=
          for root in \
            kotlin/compiler/frontend/src \
            kotlin/compiler/frontend.java/src \
            kotlin/compiler/frontend.java/serialization.java/src \
            kotlin/compiler/backend/src \
            kotlin/compiler/frontend/serialization/src \
            kotlin/compiler/cli/src \
            kotlin/compiler/cli/cli-common/src \
            kotlin/compiler/util/src \
            kotlin/compiler/jet.as.java.psi/src \
            kotlin/runtime/src; do
            if test -d "$root"; then
              find "$root" -name '*.java' ! -path '*/cli/js/*' \
                | LC_ALL=C sort >> kotlin-files
              sourcepath="$root''${sourcepath:+:$sourcepath}"
            fi
          done

          # This intermediate stage supplies the JVM compiler. Its JavaScript
          # frontend is built later with the separate source-built Dart AST.
          javac -encoding UTF-8 -source 7 -target 7 -proc:none -Xprefer:source \
            -cp "$classpath" -sourcepath "$sourcepath" \
            -d classes/kotlin @kotlin-files

          mkdir -p classes/kotlin/jet
          cp -R ${builtinsGenerator}/share/kotlin-builtins/jet/. classes/kotlin/jet/
          cp ${./ConvertBuiltinPackage.java} ConvertBuiltinPackage.java
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp "classes/kotlin:$classpath" -sourcepath "" \
            -d classes/kotlin ConvertBuiltinPackage.java
          java -cp "classes/kotlin:$classpath" ConvertBuiltinPackage \
            classes/kotlin/jet/.kotlin_package \
            classes/kotlin/jet/.kotlin_package.converted
          mv classes/kotlin/jet/.kotlin_package.converted \
            classes/kotlin/jet/.kotlin_package
          rm classes/kotlin/ConvertBuiltinPackage.class
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
          test -f smoke-classes/_DefaultPackage.class

          cat > KotlinStageCheck.java <<'JAVA'
          public final class KotlinStageCheck {
              public static void main(String[] args) {
                  if (_DefaultPackage.answer() != 42) {
                      throw new AssertionError("Kotlin compiler produced the wrong result");
                  }
              }
          }
          JAVA
          javac -proc:none -cp smoke-classes -d smoke-classes KotlinStageCheck.java
          java -cp smoke-classes KotlinStageCheck

          cat > generic.kt <<'KOTLIN'
          class Box<T>(val value: T)
          fun boxedAnswer(): Int = Box(42).value
          KOTLIN
          mkdir -p generic-classes
          java -cp "classes/kotlin:$classpath" \
            org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdkAnnotations \
            -src "$PWD/generic.kt" -output "$PWD/generic-classes" \
            > generic.log 2>&1

          cat > GenericStageCheck.java <<'JAVA'
          public final class GenericStageCheck {
              public static void main(String[] args) {
                  if (_DefaultPackage.boxedAnswer() != 42) {
                      throw new AssertionError("Kotlin generic class produced the wrong result");
                  }
              }
          }
          JAVA
          javac -proc:none -cp "generic-classes:classes/kotlin" \
            -d generic-classes GenericStageCheck.java
          java -cp "generic-classes:classes/kotlin" GenericStageCheck
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
          protobufRoot=${protobufLite}/share/protobuf-java-lite
          classpath="$root/kotlin:$coreRoot/classes:$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:$protobufRoot/classes:$root/seed"
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
      description = "August 2013 Kotlin JVM compiler with builtins generated from textual sources";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "mixed";
    };
  }
