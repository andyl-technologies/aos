##! October 2012 IntelliJ APIs required by the source-built Kotlin compiler.
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

  source = fetchgit {
    url = "https://github.com/JetBrains/intellij-community.git";
    rev = "c4c09245e19c5315fb7a5d55af8e7a56d026f570";
    name = "intellij-2012-october-kotlin-compiler-source-only";
    hash = "sha256-EHkKT1oA/mhCbageTgZq46Xproz7Ay0b9qOZfIyvrhw=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
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
  };
in
  mkDerivation {
    pname = "kotlin-idea-api-bootstrap";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.coreutils
      seed
      marchStage
      juneStage
    ];
    runtimeDeps = [buildJdk seed marchStage juneStage];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" idea

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
          for path in Path("idea").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled IntelliJ input: {path}")
              if path.read_bytes().startswith(compiled_signatures):
                  raise SystemExit(f"Compiled IntelliJ input: {path}")
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

          # Older Kotlin compiler classes must not shadow moved October APIs.
          mkdir -p classes/seed/org/jetbrains classes/idea
          ln -s "$seedRoot/dist/classes/runtime/com" classes/seed/com
          ln -s "$seedRoot/dist/classes/runtime/org/jetbrains/annotations" \
            classes/seed/org/jetbrains/annotations
          ln -s "$seedRoot/dist/classes/runtime/org/jdom" classes/seed/org/jdom

          classpath="classes/seed:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done

          cat > java-files <<'FILES'
          idea/platform/util/src/com/intellij/openapi/util/Ref.java
          idea/platform/util/src/com/intellij/util/containers/OrderedSet.java
          idea/platform/annotations/src/org/intellij/lang/annotations/MagicConstant.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/java/stubs/PsiNameValuePairStub.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/java/stubs/PsiAnnotationParameterListStub.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/java/stubs/ClsStubPsiFactory.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/compiled/InnerClassSourceStrategy.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/compiled/StubBuildingVisitor.java
          idea/java/java-psi-api/src/com/intellij/psi/util/PsiFormatUtil.java
          idea/java/java-psi-api/src/com/intellij/codeInsight/ExternalAnnotationsManager.java
          idea/java/java-psi-api/src/com/intellij/codeInsight/BaseExternalAnnotationsManager.java
          idea/platform/core-api/src/com/intellij/psi/util/PsiFormatUtilBase.java
          idea/java/java-psi-api/src/com/intellij/codeInsight/ExternalAnnotationsListener.java
          idea/java/java-psi-api/src/com/intellij/psi/util/PsiExpressionTrimRenderer.java
          idea/java/java-psi-api/src/com/intellij/psi/util/ClassUtil.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/compiled/OutOfOrderInnerClassException.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/java/stubs/impl/PsiMethodStubImpl.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/java/stubs/StubPsiFactory.java
          idea/java/java-psi-api/src/com/intellij/psi/JavaRecursiveElementVisitor.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/java/stubs/PsiMethodStub.java
          FILES

          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp "$classpath" -sourcepath "" -d classes/idea @java-files
        '';
      }
      {
        name = "check";
        script = ''
          cat > IdeaApiCheck.java <<'JAVA'
          import com.intellij.openapi.util.Ref;
          import com.intellij.util.containers.OrderedSet;

          public final class IdeaApiCheck {
              public static void main(String[] args) {
                  Ref<String> reference = Ref.create();
                  reference.set("source");
                  if (!"source".equals(reference.get())) {
                      throw new AssertionError("IntelliJ reference did not retain its value");
                  }

                  OrderedSet<String> values = new OrderedSet<String>();
                  values.add("first");
                  values.add("second");
                  values.add("first");
                  if (values.size() != 2 || !"first".equals(values.iterator().next())) {
                      throw new AssertionError("IntelliJ ordered set lost ordering or uniqueness");
                  }
              }
          }
          JAVA

          javac -proc:none -cp "classes/idea:$classpath" \
            -d classes/idea IdeaApiCheck.java
          java -cp "classes/idea:$classpath" IdeaApiCheck
          rm classes/idea/IdeaApiCheck.class
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/kotlin-idea-api"
          cp -R classes/idea "$out/share/kotlin-idea-api/classes"
        '';
      }
    ];

    meta = {
      description = "IntelliJ compiler API classes built from October 2012 source";
      homepage = "https://github.com/JetBrains/intellij-community";
      license = "mixed";
    };
  }
