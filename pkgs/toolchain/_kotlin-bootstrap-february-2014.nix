##! February 2014 Kotlin JVM compiler built from the December source stage.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2014-02-28";
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
  previousCompiler = import ./_kotlin-bootstrap-december-2013.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };
  februaryStdlib = import ./_kotlin-stdlib-february-2014.nix {
    inherit mkDerivation fetchgit fetchurl buildPackages;
  };

  javaSdkUtilSource = fetchurl {
    urls = [
      "https://raw.githubusercontent.com/JetBrains/intellij-community/a8fc158aaac530c780b2b17e492aab25d6c24425/jps/model-impl/src/org/jetbrains/jps/model/java/impl/JavaSdkUtil.java"
    ];
    hash = "sha256-CyxZ8ts0BX6eaE/FuGNNqfucgVgZvrEzo+dB0JTpdFY=";
  };

  jdkAnnotations = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "7cf587c49375d70864360d9de0fbf7873109212f";
    name = "kotlin-2014-january-jdk-annotations-source-only";
    hash = "sha256-GTYjOnSwaG/w71vHuSOpC9FaPRVj/O5pmzJ5ue3LaEM=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
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
    ];
  };

  source = fetchgit {
    url = "https://github.com/JetBrains/kotlin.git";
    rev = "9efdd136ba075b7aa27d3f72587180ca5688cba3";
    name = "kotlin-2014-february-compiler-source-only";
    hash = "sha256-Fgf4idzVIhso6JZ4CMOSD9DvjWLMoZ/VbUKeU7q+R00=";
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
      "/compiler/builtins-serializer/src/"
      "/core/builtins/native/"
      "/core/builtins/src/"
      "/core/descriptors/src/"
      "/core/descriptor.loader.java/src/"
      "/core/serialization.java/src/"
      "/core/util.runtime/src/"
      "/libraries/stdlib/src/"
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
      previousCompiler
      februaryStdlib
    ];
    runtimeDeps = [
      buildJdk
      seed
      marchStage
      juneStage
      octoberApi
      ideaCore
      protobufLite
      previousCompiler
      februaryStdlib
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" kotlin
          chmod -R u+w kotlin
          cp -R ${./kotlin-bootstrap/idea-2013} idea
          chmod -R u+w idea
          mkdir -p idea/jps/model-impl/src/org/jetbrains/jps/model/java/impl
          cp ${javaSdkUtilSource} \
            idea/jps/model-impl/src/org/jetbrains/jps/model/java/impl/JavaSdkUtil.java
          chmod u+w idea/jps/model-impl/src/org/jetbrains/jps/model/java/impl/JavaSdkUtil.java
          mkdir -p idea/java/java-psi-api/src/com/intellij/psi/compiled
          cp ${./kotlin-february/compat/ClassFileDecompilers.java} \
            idea/java/java-psi-api/src/com/intellij/psi/compiled/ClassFileDecompilers.java
          python3 - <<'PYTHON'
          from pathlib import Path

          source = Path("idea/jps/model-impl/src/org/jetbrains/jps/model/java/impl/JavaSdkUtil.java")
          text = source.read_text()
          replacements = {
              "ContainerUtil.newTroveSet(FileUtil.PATH_HASHING_STRATEGY)": "new java.util.HashSet<String>()",
              "ContainerUtil.newArrayList()": "new java.util.ArrayList<File>()",
          }
          for old, new in replacements.items():
              if text.count(old) != 1:
                  raise SystemExit(f"Unexpected JavaSdkUtil source: {old}")
              text = text.replace(old, new)
          source.write_text(text)
          PYTHON
          cp -R ${jdkAnnotations}/jdk-annotations jdk-annotations
          chmod -R u+w jdk-annotations
          cp -R ${./kotlin-february-annotations}/. jdk-annotations/

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
          for root in (Path("kotlin"), Path("idea"), Path("jdk-annotations")):
              for path in root.rglob("*"):
                  if not path.is_file():
                      continue
                  if path.suffix.lower() in forbidden_suffixes or path.name.startswith(".kotlin_"):
                      raise SystemExit(f"Compiled bootstrap input: {path}")
                  if path.read_bytes().startswith(compiled_signatures):
                      raise SystemExit(f"Compiled bootstrap input: {path}")
          PY

          patch -d kotlin -p1 < ${./kotlin-february/patches/february-compiler.patch}
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
          previousRoot=${previousCompiler}/share/kotlin-bootstrap
          stdlibRoot=${februaryStdlib}/share/kotlin-stdlib

          mkdir -p classes/parser classes/seed/org/jetbrains classes/storage \
            classes/core classes/plugin classes/cli classes/metadata/jet \
            classes/legacy-runtime
          ln -s "$previousRoot/core/jet" classes/legacy-runtime/jet
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

          previousClasspath="classes/parser:$previousRoot/metadata:$previousRoot/cli:$previousRoot/core:$previousRoot/plugin:$previousRoot/light:$previousRoot/storage:$baseClasspath"
          java -cp "$previousClasspath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk -noJdkAnnotations \
            -classpath "${classpathJdk}/jre/lib/rt.jar:$previousRoot/core" \
            -annotations "$PWD/jdk-annotations" \
            -src "$PWD/kotlin/libraries/stdlib/src:$PWD/kotlin/core/util.runtime/src:$PWD/kotlin/compiler/backend-common/src/output.kt" \
            -output "$PWD/classes/storage" > storage.log 2>&1

          coreClasspath="classes/storage:$previousRoot/core:$baseClasspath"
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
            core/builtins/src; do
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
            idea/platform/util/src/com/intellij/util/containers/SLRUCache.java \
            idea/java/java-psi-impl/src/com/intellij/psi/impl/light/LightTypeParameterListBuilder.java \
            idea/jps/model-impl/src/org/jetbrains/jps/model/java/impl/JavaSdkUtil.java \
            >> core-files

          # The February frontend introduces Kotlin classes referenced by its
          # Java sources. Compile signatures first, then replace them with the
          # classes compiled from the matching Kotlin sources below.
          find ${./kotlin-february/stubs} -name '*.java' \
            | LC_ALL=C sort >> core-files

          javac -encoding UTF-8 -source 7 -target 7 -proc:none -Xprefer:source -Xmaxerrs 10000 \
            -cp "$coreClasspath" -sourcepath "$sourcepath" \
            -d classes/core @core-files > core.log 2>&1
          cp -R kotlin/compiler/frontend.java/src/META-INF classes/core/

          mkdir -p classes/core-kotlin
          kotlinCoreClasspath="classes/core:classes/storage:$stdlibRoot/classes:${classpathJdk}/jre/lib/rt.jar:$baseClasspath"
          java -cp "$previousClasspath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk -noJdkAnnotations \
            -classpath "$kotlinCoreClasspath" \
            -annotations "$PWD/jdk-annotations" \
            -src "$PWD/kotlin/core/descriptors/src:$PWD/kotlin/core/descriptor.loader.java/src:$PWD/kotlin/compiler/frontend/src:$PWD/kotlin/compiler/frontend.java/src:$PWD/kotlin/compiler/util/src" \
            -output "$PWD/classes/core-kotlin" > core-kotlin.log 2>&1
          cp -R classes/core-kotlin/. classes/core/

          # Recompile Java against the real Kotlin classes so no bootstrap
          # signatures survive in the installed compiler.
          sed '\|^${./kotlin-february/stubs}/|d' core-files > core-real-files
          javac -encoding UTF-8 -source 7 -target 7 -proc:none -Xprefer:source \
            -cp "classes/core-kotlin:$coreClasspath" -sourcepath "$sourcepath" \
            -d classes/core @core-real-files > core-real.log 2>&1

          mkdir -p classes/light classes/storage-api/org/jetbrains/jet
          mkdir -p light-src
          cp ${./kotlin-february/light-stubs/LightClassUtil.java} light-src/LightClassUtil.java
          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp "classes/core:$coreClasspath:$stdlibRoot/classes" -sourcepath "" \
            -d classes/light \
            kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/light/*.java \
            kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/KotlinLightModifierList.java \
            kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/KotlinLightParameter.java \
            kotlin/compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/messages/CompilerMessageLocation.java \
            kotlin/compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/messages/CompilerMessageSeverity.java \
            kotlin/compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/messages/MessageCollector.java \
            kotlin/compiler/cli/cli-common/src/org/jetbrains/jet/cli/common/messages/OutputMessageUtil.java \
            light-src/LightClassUtil.java \
            kotlin/compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/ModuleChunk.java

          # Keep compiler APIs while excluding the stage's stdlib classes.
          cp -R classes/storage/org/jetbrains/jet/storage \
            classes/storage-api/org/jetbrains/jet/
          cp classes/storage/org/jetbrains/jet/OutputFile.class \
            classes/storage/org/jetbrains/jet/OutputFileCollection.class \
            classes/storage/org/jetbrains/jet/SimpleOutputFile.class \
            classes/storage/org/jetbrains/jet/SimpleOutputFileCollection.class \
            classes/storage-api/org/jetbrains/jet/

          # Compile plugin helpers against the already-built February stdlib.
          # Repeating its sources here creates duplicate Kotlin declarations.
          pluginClasspath="classes/light:classes/storage-api:classes/core:classes/seed:$coreRoot/classes:$apiRoot/classes:$protobufRoot/classes:$stdlibRoot/classes:${classpathJdk}/jre/lib/rt.jar"
          java -cp "$previousClasspath" org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk -noJdkAnnotations \
            -classpath "$pluginClasspath" \
            -annotations "$PWD/jdk-annotations" \
            -src "$PWD/kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/KotlinLightMethodForDeclaration.kt:$PWD/kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/KotlinLightClass.kt:$PWD/kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/LightClassStubWithData.kt:$PWD/kotlin/compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/lightClassUtils.kt:$PWD/kotlin/compiler/cli/src/org/jetbrains/jet/cli/common/output/outputDirectors.kt:$PWD/kotlin/compiler/cli/src/org/jetbrains/jet/cli/common/output/outputUtils.kt:$PWD/kotlin/compiler/cli/src/org/jetbrains/jet/cli/jvm/compiler/ChunkAsOneModule.kt" \
            -output "$PWD/classes/plugin" > plugin.log 2>&1

          cliClasspath="classes/core:classes/light:classes/plugin:classes/storage:$stdlibRoot/classes:classes/legacy-runtime:$baseClasspath"
          sourcepath=
          for root in compiler/cli/src compiler/cli/cli-common/src compiler/jet.as.java.psi/src; do
            find "kotlin/$root" -name '*.java' ! -path '*/cli/js/*' \
              ! -name 'PrintingLogger.java' | LC_ALL=C sort >> cli-files
            sourcepath="kotlin/$root''${sourcepath:+:$sourcepath}"
          done
          printf '%s\n' \
            idea/java/java-psi-api/src/com/intellij/psi/compiled/ClassFileDecompilers.java \
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

          # The real CLI class supersedes the light-stage signature.
          rm classes/light/org/jetbrains/jet/asJava/LightClassUtil*.class
          rm -R classes/light/org/jetbrains/jet/cli/common/messages

          cp -R "$previousRoot/metadata/jet/." classes/metadata/jet/

          mkdir -p classes/generator classes/generated-builtins
          java -cp "classes/parser:classes/metadata:classes/cli:$cliClasspath" \
            org.jetbrains.jet.cli.jvm.K2JVMCompiler \
            -noStdlib -noJdk \
            -classpath "$stdlibRoot/classes:${classpathJdk}/jre/lib/rt.jar:classes/cli:$cliClasspath" \
            -annotations "$PWD/jdk-annotations" \
            -src "$PWD/kotlin/compiler/builtins-serializer/src" \
            -output "$PWD/classes/generator" > generator.log 2>&1
          java -cp "classes/generator:classes/metadata:classes/cli:$cliClasspath:$stdlibRoot/classes:${classpathJdk}/jre/lib/rt.jar" \
            org.jetbrains.jet.utils.builtinsSerializer.BuiltinsSerializerPackage \
            "$PWD/classes/generated-builtins" \
            "$PWD/kotlin/core/builtins/native" \
            "$PWD/kotlin/core/builtins/src" > generated.log 2>&1

          # The previous index permits the serializer to initialize. Replace
          # it with metadata serialized from February's textual builtins.
          rm -R classes/metadata/jet
          cp -R classes/generated-builtins/jet classes/metadata/jet
        '';
      }
      {
        name = "check";
        script = ''
          python3 - <<'PY'
          from pathlib import Path

          for root in ("core", "light", "plugin", "cli"):
              for path in Path("classes", root).rglob("*.class"):
                  if b"build-only signature" in path.read_bytes():
                      raise SystemExit(f"Bootstrap signature survived: {path}")
          PY

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
          test "$(find classes/metadata/jet -name '*.kotlin_class' | wc -l)" -eq 214
          test -s classes/cli/org/jetbrains/jet/asJava/LightClassUtil.class
          test -s classes/plugin/org/jetbrains/jet/asJava/AsJavaPackage.class
          test -s classes/metadata/jet/inline.kotlin_class
          test -s classes/metadata/jet/noinline.kotlin_class

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
            classes/legacy-runtime \
            classes/plugin classes/cli classes/metadata \
            "$out/share/kotlin-bootstrap/"
        '';
      }
    ];

    meta = {
      description = "February 2014 Kotlin JVM compiler compiled from source";
      homepage = "https://github.com/JetBrains/kotlin";
      license = "Apache-2.0";
    };
  }
