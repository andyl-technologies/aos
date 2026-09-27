##! Source-built headless IntelliJ environment for the Kotlin compiler bootstrap.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
}: let
  version = "2012-05-23";
  buildJdk = buildPackages.openjdk-8;
  # The 2012 class reader understands JDK 7 bytecode.
  probeJdk = buildPackages.openjdk-7;
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

  source = fetchgit {
    url = "https://github.com/JetBrains/intellij-community.git";
    rev = "9ee45ddefe9c11aa5b2e93510c62ec5b1da843c0";
    name = "intellij-2012-may-kotlin-compiler-source-only";
    hash = "sha256-/0Ghv8JgQu+XYKsAHqBttZjtc/9rY7zt8jMn0K8Ziv4=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/platform/util/src/"
      "/platform/util-rt/src/"
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
    pname = "kotlin-idea-core-bootstrap";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      probeJdk
      buildPackages.python3
      buildPackages.coreutils
      seed
      marchStage
      juneStage
      octoberApi
    ];
    runtimeDeps = [buildJdk seed marchStage juneStage octoberApi];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" idea
          chmod -R u+w idea

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

          vfs = Path("idea/platform/core-api/src/com/intellij/openapi/vfs/VfsUtilCore.java")
          source = vfs.read_text()
          original = "StandardFileSystems.FILE_PROTOCOL"
          if source.count(original) != 1:
              raise SystemExit("IntelliJ VFS protocol compatibility patch did not match")
          vfs.write_text(source.replace(original, '"file"'))

          path_util = Path("idea/platform/core-api/src/com/intellij/util/PathUtil.java")
          source = path_util.read_text()
          replacements = {
              "import com.intellij.openapi.vfs.StandardFileSystems;\n": "",
              "import org.jetbrains.annotations.Nullable;":
                  "import org.jetbrains.annotations.Nullable;\n\nimport java.io.File;",
              "StandardFileSystems.JAR_PROTOCOL": '"jar"',
              "StandardFileSystems.JAR_SEPARATOR": '"!/"',
              "StandardFileSystems.getVirtualFileForJar(file)": "getVirtualFileForJar(file)",
              "PathManager.getJarPathForClass(aClass)":
                  "new File(PathManager.getResourceRoot(aClass, \"/\" + aClass.getName().replace('.', '/') + \".class\")).getAbsolutePath()",
          }
          for original, replacement in replacements.items():
              if original not in source:
                  raise SystemExit("IntelliJ path compatibility patch did not match")
              source = source.replace(original, replacement)

          original = "public class PathUtil {\n"
          helper = "\n".join((
              "public class PathUtil {",
              "  @Nullable",
              "  private static VirtualFile getVirtualFileForJar(@Nullable VirtualFile file) {",
              "    if (file == null) return null;",
              "    String path = file.getPath();",
              '    int separator = path.indexOf("!/");',
              "    if (separator < 0) return null;",
              '    return VirtualFileManager.getInstance().getFileSystem("file").findFileByPath(path.substring(0, separator));',
              "  }",
              "",
          )) + "\n"
          if source.count(original) != 1:
              raise SystemExit("IntelliJ JAR path compatibility patch did not match")
          path_util.write_text(source.replace(original, helper))

          file_manager = Path(
              "idea/platform/core-impl/src/com/intellij/psi/impl/file/impl/FileManagerImpl.java"
          )
          source = file_manager.read_text()
          # The earlier headless VFS can return empty child entries.
          original = "if (vFile.isDirectory()) return null;"
          if source.count(original) != 1:
              raise SystemExit("IntelliJ file manager compatibility patch did not match")
          file_manager.write_text(
              source.replace(original, "if (vFile == null || vFile.isDirectory()) return null;")
          )

          local_file = Path(
              "idea/platform/core-impl/src/com/intellij/openapi/vfs/local/CoreLocalVirtualFile.java"
          )
          source = local_file.read_text()
          # BOM detection requires mark/reset on local file streams.
          original = "new FileInputStream(myIoFile), this"
          if source.count(original) != 1:
              raise SystemExit("IntelliJ local VFS stream patch did not match")
          local_file.write_text(source.replace(
              original, "new BufferedInputStream(new FileInputStream(myIoFile)), this"
          ))

          jar_system = Path(
              "idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/jar/CoreJarFileSystem.java"
          )
          source = jar_system.read_text()
          for original, replacement in (
              ("import com.intellij.openapi.vfs.StandardFileSystems;\n", ""),
              ("StandardFileSystems.JAR_PROTOCOL", '"jar"'),
          ):
              if source.count(original) != 1:
                  raise SystemExit("IntelliJ JAR VFS protocol patch did not match")
              source = source.replace(original, replacement)
          jar_system.write_text(source)
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

          mkdir -p classes/seed/org/jetbrains classes/idea
          ln -s "$seedRoot/dist/classes/runtime/com" classes/seed/com
          ln -s "$seedRoot/dist/classes/runtime/org/jetbrains/annotations" \
            classes/seed/org/jetbrains/annotations
          ln -s "$seedRoot/dist/classes/runtime/org/jdom" classes/seed/org/jdom

          classpath="$apiRoot/classes:$juneRoot/idea:$juneRoot/java-deps:$marchRoot/idea:$marchRoot/api:classes/seed"
          for dependency in asm asm4 trove pico guava jsr305 cli jna; do
            classpath="$classpath:$seedRoot/deps/$dependency"
          done

          cat > java-files <<'FILES'
          idea/platform/core-impl/src/com/intellij/core/CoreApplicationEnvironment.java
          idea/platform/core-impl/src/com/intellij/core/CoreProjectEnvironment.java
          idea/java/java-psi-impl/src/com/intellij/core/JavaCoreApplicationEnvironment.java
          idea/java/java-psi-impl/src/com/intellij/core/JavaCoreProjectEnvironment.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/source/tree/CoreJavaASTFactory.java
          idea/platform/core-api/src/com/intellij/openapi/components/ExtensionAreas.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/FileSystemPersistence.java
          idea/platform/core-impl/src/com/intellij/psi/PsiReferenceServiceImpl.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/VirtualFileManagerImpl.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/pointers/VirtualFilePointerManager.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/CoreVirtualFilePointerManager.java
          idea/platform/core-api/src/com/intellij/openapi/progress/EmptyProgressIndicator.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/PsiExpressionEvaluator.java
          idea/java/java-psi-impl/src/com/intellij/core/CorePsiPackageImplementationHelper.java
          idea/java/java-psi-impl/src/com/intellij/core/CoreJavaDirectoryService.java
          idea/java/java-psi-api/src/com/intellij/openapi/projectRoots/JavaVersionService.java
          idea/java/java-psi-impl/src/com/intellij/core/CoreJavaCodeStyleSettingsFacade.java
          idea/java/java-psi-impl/src/com/intellij/core/CoreJavaCodeStyleManager.java
          idea/platform/core-impl/src/com/intellij/psi/impl/PsiManagerImpl.java
          idea/platform/core-impl/src/com/intellij/psi/impl/cache/impl/CacheUtil.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/pointers/VirtualFilePointer.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/pointers/VirtualFilePointerContainer.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/pointers/VirtualFilePointerListener.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/CachingVirtualFileSystem.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/events/VFilePropertyChangeEvent.java
          idea/platform/util/src/com/intellij/util/EventDispatcher.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/ex/VirtualFileManagerEx.java
          idea/java/java-psi-api/src/com/intellij/openapi/projectRoots/JavaSdkVersion.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/source/javadoc/CorePsiDocTagValueImpl.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/source/javadoc/PsiDocTokenImpl.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/source/tree/java/PsiIdentifierImpl.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/source/tree/java/PsiJavaTokenImpl.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/source/tree/java/PsiKeywordImpl.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/IdentityVirtualFilePointer.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/VirtualFilePointerContainerImpl.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/BulkVirtualFileListenerAdapter.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/VirtualFilePointerEx.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/events/VFileContentChangeEvent.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/events/VFileCopyEvent.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/events/VFileCreateEvent.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/events/VFileDeleteEvent.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/newvfs/events/VFileMoveEvent.java
          idea/java/java-psi-api/src/com/intellij/psi/codeStyle/JavaCodeStyleManager.java
          idea/platform/core-api/src/com/intellij/psi/codeStyle/SuggestedNameInfo.java
          idea/platform/util-rt/src/com/intellij/util/containers/ContainerUtilRt.java
          idea/platform/core-api/src/com/intellij/openapi/vfs/VfsUtilCore.java
          idea/platform/core-api/src/com/intellij/util/PathUtil.java
          idea/platform/util-rt/src/com/intellij/util/ArrayUtilRt.java
          idea/java/java-psi-api/src/com/intellij/psi/augment/PsiAugmentProvider.java
          idea/platform/core-impl/src/com/intellij/psi/impl/file/impl/FileManagerImpl.java
          idea/java/java-psi-impl/src/com/intellij/psi/impl/compiled/DefaultClsStubBuilderFactory.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/local/CoreLocalVirtualFile.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/jar/CoreJarFileSystem.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/jar/CoreJarHandler.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/jar/CoreJarVirtualFile.java
          idea/platform/core-impl/src/com/intellij/openapi/vfs/impl/jar/JarHandlerBase.java
          idea/platform/util/src/com/intellij/openapi/util/io/FileAttributes.java
          FILES

          javac -encoding UTF-8 -source 7 -target 7 -proc:none \
            -cp "$classpath" -sourcepath "" -d classes/idea @java-files

          mkdir -p classes/idea/messages
          cp idea/java/java-psi-api/src/messages/JavaCoreBundle.properties \
            classes/idea/messages/
          cp idea/java/java-psi-impl/src/messages/JavaErrorMessages.properties \
            classes/idea/messages/
        '';
      }
      {
        name = "check";
        script = ''
          cat > IdeaCoreCheck.java <<'JAVA'
          import com.intellij.core.JavaCoreApplicationEnvironment;
          import com.intellij.core.JavaCoreProjectEnvironment;
          import com.intellij.openapi.Disposable;
          import com.intellij.openapi.util.Disposer;
          import com.intellij.openapi.vfs.VirtualFile;
          import com.intellij.openapi.vfs.VirtualFileManager;
          import com.intellij.psi.JavaPsiFacade;
          import com.intellij.psi.PsiClass;
          import com.intellij.psi.search.GlobalSearchScope;
          import java.io.File;
          import java.util.ResourceBundle;

          public final class IdeaCoreCheck {
              public static void main(String[] args) {
                  Disposable owner = Disposer.newDisposable();
                  JavaCoreApplicationEnvironment application =
                      new JavaCoreApplicationEnvironment(owner);
                  JavaCoreProjectEnvironment project =
                      new JavaCoreProjectEnvironment(owner, application);

                  if (project.getProject() == null || VirtualFileManager.getInstance() == null) {
                      throw new AssertionError("Headless IntelliJ environment did not initialize");
                  }

                  File runtime = new File("${probeJdk}/jre/lib/rt.jar");
                  VirtualFile jar = application.getJarFileSystem().findFileByPath(runtime + "!/");
                  if (jar == null || jar.findFileByRelativePath("java/lang/Object.class") == null) {
                      throw new AssertionError("JDK classes are missing from the JAR VFS");
                  }

                  project.addToClasspath(runtime);
                  PsiClass objectClass = JavaPsiFacade.getInstance(project.getProject()).findClass(
                      "java.lang.Object", GlobalSearchScope.allScope(project.getProject()));
                  if (objectClass == null) {
                      throw new AssertionError("The headless PSI could not read a JDK class");
                  }

                  ResourceBundle.getBundle("messages.JavaCoreBundle");

                  Disposer.dispose(owner);
              }
          }
          JAVA

          javac -proc:none -cp "classes/idea:$classpath" \
            -d classes/idea IdeaCoreCheck.java
          java -cp "classes/idea:$classpath" IdeaCoreCheck
          rm classes/idea/IdeaCoreCheck.class
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/kotlin-idea-core"
          cp -R classes/idea "$out/share/kotlin-idea-core/classes"
        '';
      }
    ];

    meta = {
      description = "Headless IntelliJ environment built from May 2012 source";
      homepage = "https://github.com/JetBrains/intellij-community";
      license = "mixed";
    };
  }
