##! November 2013 Kotlin JVM compiler built from the August source stage.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2013-11-29";
  buildJdk = buildPackages.openjdk-8;
  classpathJdk = buildPackages.openjdk-7;
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
  augustCompiler = import ./_kotlin-bootstrap-serialized-2013.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  novemberStdlib = import ./_kotlin-stdlib-november-2013.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  source = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "08befe02eecc608ed4566d5d6950075389afcb62";
    name = "kotlin-2013-november-compiler-source-only";
    hash = "sha256-wYuy/jJol4dsxiATf6w5g12f4oYrvQU3THwQguYHGNg=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/compiler/backend/src/"
      "/compiler/backend-common/src/"
      "/compiler/cli/src/"
      "/compiler/cli/cli-common/src/"
      "/compiler/frontend.java/src/"
      "/compiler/frontend.java/serialization.java/src/"
      "/compiler/frontend/src/"
      "/compiler/frontend/serialization/src/"
      "/compiler/jet.as.java.psi/src/"
      "/compiler/util/src/"
      "/core/descriptors/src/"
      "/core/descriptor.loader.java/src/"
      "/core/serialization.java/src/"
      "/core/util.runtime/src/"
      "/runtime/src/"
      "/libraries/stdlib/src/"
      "/jdk-annotations/"
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
      classpathJdk
      buildPackages.python3
      buildPackages.findutils
      buildPackages.coreutils
      buildPackages.patch
      seed
      marchStage
      juneStage
      octoberApi
      ideaCore
      protobufLite
      augustCompiler
      novemberStdlib
    ];
    runtimeDeps = [
      buildJdk
      seed
      marchStage
      juneStage
      octoberApi
      ideaCore
      protobufLite
      novemberStdlib
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" kotlin
          chmod -R u+w kotlin
          cp -R ${./kotlin-bootstrap/idea-2013} idea

          python3 - <<'PY'
          from pathlib import Path

          forbidden_suffixes = {
              ".bin", ".class", ".dll", ".dylib", ".exe", ".jar", ".so", ".wasm",
              ".kotlin_class", ".kotlin_name_table", ".kotlin_class_names", ".kotlin_package",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("feedface"),
              bytes.fromhex("feedfacf"), bytes.fromhex("4d5a"),
          )
          for root in (Path("kotlin"), Path("idea")):
              for path in root.rglob("*"):
                  if not path.is_file():
                      continue
                  if path.suffix.lower() in forbidden_suffixes or path.name.startswith(".kotlin_"):
                      raise SystemExit(f"Compiled bootstrap input: {path}")
                  if path.read_bytes().startswith(compiled_signatures):
                      raise SystemExit(f"Compiled bootstrap input: {path}")
          PY

          patch -d kotlin -p1 < ${./kotlin-bootstrap/patches/november-compiler.patch}
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
          augustRoot=${augustCompiler}/share/kotlin-bootstrap
          stdlibRoot=${novemberStdlib}/share/kotlin-stdlib

          mkdir -p classes/parser classes/seed/org/jetbrains classes/storage \
            classes/core classes/plugin classes/cli classes/metadata/jet \
            classes/converted
          ln -s "$seedRoot/dist/classes/runtime/com" classes/seed/com
          ln -s "$seedRoot/dist/classes/runtime/org/jetbrains/annotations" \
            classes/seed/org/jetbrains/annotations
          ln -s "$seedRoot/dist/classes/runtime/org/jdom" classes/seed/org/jdom
          ln -s "$seedRoot/dist/classes/runtime/org/apache" classes/seed/org/apache

          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -d classes/parser ${./kotlin-bootstrap}/SAXParser.java

          baseClasspath="$coreRoot/classes:$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:$protobufRoot/classes:classes/seed"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            baseClasspath="$baseClasspath:$seedRoot/deps/$dependency"
          done

          augustClasspath="classes/parser:$augustRoot/kotlin:$baseClasspath:$augustRoot/seed"
          java -cp "$augustClasspath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk -noJdkAnnotations \
            -classpath "$stdlibRoot/modules:${classpathJdk}/jre/lib/rt.jar:$augustRoot/kotlin" \
            -annotations "$PWD/kotlin/jdk-annotations" \
            -src "$PWD/kotlin/libraries/stdlib/src:$PWD/kotlin/core/util.runtime/src/org/jetbrains/jet/storage/storage.kt:$PWD/kotlin/compiler/backend-common/src/output.kt" \
            -output "$PWD/classes/storage" > storage.log 2>&1

          coreClasspath="classes/storage:$baseClasspath"
          sourcepath=
          for root in \
            core/descriptors/src \
            core/descriptor.loader.java/src \
            core/serialization.java/src \
            core/util.runtime/src \
            compiler/frontend/src \
            compiler/frontend.java/src \
            compiler/frontend.java/serialization.java/src \
            compiler/backend/src \
            compiler/backend-common/src \
            compiler/frontend/serialization/src \
            compiler/util/src \
            runtime/src; do
            if test -d "kotlin/$root"; then
              find "kotlin/$root" -name '*.java' ! -path '*/cli/js/*' \
                ! -name 'PrintingLogger.java' | LC_ALL=C sort >> core-files
              sourcepath="kotlin/$root''${sourcepath:+:$sourcepath}"
            fi
          done

          printf '%s\n' \
            idea/platform/util/src/com/intellij/openapi/util/NullableLazyValue.java \
            idea/platform/util/src/com/intellij/openapi/util/AtomicNotNullLazyValue.java \
            idea/platform/util/src/com/intellij/util/containers/ConcurrentMultiMap.java \
            idea/java/java-psi-impl/src/com/intellij/psi/impl/light/LightTypeParameterListBuilder.java \
            >> core-files

          javac -encoding UTF-8 -source 7 -target 7 -proc:none -Xprefer:source \
            -cp "$coreClasspath" -sourcepath "$sourcepath" \
            -d classes/core @core-files > core.log 2>&1

          mkdir -p classes/light classes/storage-api/org/jetbrains/jet
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp "classes/core:$coreClasspath:$stdlibRoot/modules" -sourcepath "" \
            -d classes/light \
            kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/light/*.java \
            kotlin/compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/ModuleChunk.java

          # Keep compiler APIs while excluding the stage's stdlib classes.
          cp -R classes/storage/org/jetbrains/jet/storage \
            classes/storage-api/org/jetbrains/jet/
          cp classes/storage/org/jetbrains/jet/OutputFile.class \
            classes/storage/org/jetbrains/jet/OutputFileCollection.class \
            classes/storage/org/jetbrains/jet/SimpleOutputFile.class \
            classes/storage/org/jetbrains/jet/SimpleOutputFileCollection.class \
            classes/storage-api/org/jetbrains/jet/

          # The August reader requires JDK 7 class files and one source module
          # for the November library and Kotlin light-method implementation.
          pluginClasspath="classes/light:classes/storage-api:classes/core:classes/seed:$coreRoot/classes:$apiRoot/classes:$protobufRoot/classes:$stdlibRoot/modules:${classpathJdk}/jre/lib/rt.jar:$augustRoot/kotlin"
          java -cp "$augustClasspath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk -noJdkAnnotations \
            -classpath "$pluginClasspath" \
            -annotations "$PWD/kotlin/jdk-annotations" \
            -src "$PWD/kotlin/libraries/stdlib/src:$PWD/kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/KotlinLightMethodForDeclaration.kt:$PWD/kotlin/compiler/cli/src/org/jetbrains/jet/cli/common/output/outputDirectors.kt:$PWD/kotlin/compiler/cli/src/org/jetbrains/jet/cli/common/output/outputUtils.kt:$PWD/kotlin/compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/ChunkAsOneModule.kt" \
            -output "$PWD/classes/plugin" > plugin.log 2>&1

          cliClasspath="classes/core:classes/light:classes/plugin:classes/storage:$baseClasspath"
          sourcepath=
          for root in compiler/cli/src compiler/cli/cli-common/src compiler/jet.as.java.psi/src; do
            find "kotlin/$root" -name '*.java' ! -path '*/cli/js/*' \
              ! -name 'PrintingLogger.java' | LC_ALL=C sort >> cli-files
            sourcepath="kotlin/$root''${sourcepath:+:$sourcepath}"
          done
          printf '%s\n' \
            idea/java/java-psi-impl/src/com/intellij/psi/impl/source/PsiExtensibleClass.java \
            idea/platform/util/src/com/intellij/util/containers/SLRUCache.java \
            idea/platform/util/src/com/intellij/openapi/util/NullableLazyValue.java \
            idea/platform/util/src/com/intellij/openapi/util/AtomicNotNullLazyValue.java \
            idea/platform/util/src/com/intellij/util/containers/ConcurrentMultiMap.java \
            idea/java/java-psi-impl/src/com/intellij/psi/impl/light/LightTypeParameterListBuilder.java \
            >> cli-files

          javac -encoding UTF-8 -source 7 -target 7 -proc:none -Xprefer:source \
            -cp "$cliClasspath" -sourcepath "$sourcepath" \
            -d classes/cli @cli-files > cli.log 2>&1

          cp "$augustRoot/kotlin/jet/"*.kotlin_class classes/metadata/jet/
          cp "$augustRoot/kotlin/jet/.kotlin_name_table" \
            "$augustRoot/kotlin/jet/.kotlin_class_names" \
            "$augustRoot/kotlin/jet/.kotlin_package" \
            classes/metadata/jet/
          chmod -R u+w classes/metadata/jet
          cp ${./kotlin-bootstrap/ConvertNovemberBuiltinClasses.java} \
            ConvertNovemberBuiltinClasses.java
          javac -encoding UTF-8 -source 8 -target 8 -proc:none \
            -cp "classes/cli:$cliClasspath" -sourcepath "" \
            -d classes/converted ConvertNovemberBuiltinClasses.java
          java -cp "classes/converted:classes/cli:$cliClasspath" \
            ConvertNovemberBuiltinClasses classes/metadata > metadata.log 2>&1
        '';
      }
      {
        name = "check";
        script = ''
          cat > smoke.kt <<'KOTLIN'
          fun answer(): Int = 40 + 2
          KOTLIN

          mkdir -p classes/smoke
          java -cp "classes/parser:classes/metadata:classes/cli:$cliClasspath" \
            org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdkAnnotations \
            -src "$PWD/smoke.kt" -output "$PWD/classes/smoke" \
            > smoke.log 2>&1
          test -s classes/smoke/_DefaultPackage.class
          test "$(find classes/core classes/cli -name '*.class' | wc -l)" -ge 2100
          test "$(cat metadata.log)" = "Converted 197 builtin classes"

          cat > KotlinStageCheck.java <<'JAVA'
          public final class KotlinStageCheck {
              public static void main(String[] args) {
                  if (_DefaultPackage.answer() != 42) {
                      throw new AssertionError("Kotlin compiler produced the wrong result");
                  }
              }
          }
          JAVA
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp classes/smoke -d classes/smoke KotlinStageCheck.java
          java -cp "classes/smoke:classes/storage:$baseClasspath" KotlinStageCheck
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/kotlin-bootstrap"
          cp -R classes/parser classes/storage classes/core classes/light \
            classes/plugin classes/cli classes/metadata \
            "$out/share/kotlin-bootstrap/"
        '';
      }
    ];

    meta = {
      description = "November 2013 Kotlin JVM compiler compiled from source";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "Apache-2.0";
    };
  }
