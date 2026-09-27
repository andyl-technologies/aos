##! Bazel Java tool repository compiled from source without a release ZIP.
{
  mkDerivation,
  buildPackages,
  bazelSource,
  bazelBootstrap,
  bazelAsm,
  bazelJacoco,
  bazelProguard,
  bazelErrorProne,
  mavenRepositories,
}: let
  jdk = buildPackages.openjdk-21;
  dependencyRepositories = mavenRepositories ++ bazelErrorProne;
  repositoryPaths = builtins.concatStringsSep " " (builtins.map (path: "'${path}'") dependencyRepositories);
  asmSourceInstall = builtins.concatStringsSep "\n" (builtins.map (
      archive: ''
        cp ${archive.src} "$out/java_tools/third_party/java/jacoco/${archive.component}-${archive.version}-sources.jar"
      ''
    )
    (builtins.filter (archive: archive.version == "9.6") bazelAsm.passthru.sourceArchives));
in
  mkDerivation {
    pname = "bazel-remote-java-tools-source";
    version = "8.6.0";

    buildDeps =
      [
        jdk
        buildPackages.python3
        buildPackages.findutils
        buildPackages.unzip
        bazelBootstrap
        bazelAsm
        bazelJacoco
        bazelProguard
      ]
      ++ dependencyRepositories;
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -a ${bazelSource}/third_party/jarjar/java jarjar-source
          chmod -R u+w jarjar-source

          # Source-built dependencies contain sealed classes and records.
          # Preserve that metadata through Jarjar's existing ASM visitors.
          python3 - <<'PY'
          from pathlib import Path

          root = Path("jarjar-source/com/tonicsystems/jarjar")
          expected = {
              "StringReader.java": 4,
              "EmptyClassVisitor.java": 4,
              "util/GetNameClassWriter.java": 1,
          }
          for relative, count in expected.items():
              path = root / relative
              source = path.read_text()
              if source.count("Opcodes.ASM7") != count:
                  raise SystemExit(f"unexpected Jarjar ASM visitor layout: {relative}")
              path.write_text(source.replace("Opcodes.ASM7", "Opcodes.ASM9"))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          find ${repositoryPaths} ${bazelAsm}/share/java ${bazelJacoco}/share/java \
            -name '*.jar' ! -name '*-sources.jar' -type f -print | sort -u > dependencies
          printf '%s\n' ${bazelBootstrap}/share/java/libblaze.jar >> dependencies
          classpath=$(paste -sd: dependencies)

          # Upstream's jarjar_command target excludes the Ant/Maven plugins.
          find ${bazelSource}/src/java_tools/buildjar/java \
            ${bazelSource}/src/java_tools/junitrunner/java \
            jarjar-source \
            -name '*.java' -type f \
            ! -path '*/com/tonicsystems/jarjar/util/AntJarProcessor.java' \
            ! -path '*/com/tonicsystems/jarjar/JarJarMojo.java' \
            ! -path '*/com/tonicsystems/jarjar/JarJarTask.java' \
            -print | sort > sources
          mkdir -p classes generated runtime-classes
          javac -source 21 -target 21 -encoding UTF-8 \
            --add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.comp=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.main=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.model=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.processing=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.resources=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED \
            --add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED \
            -cp "$classpath" \
            -processor com.google.auto.value.processor.AutoValueProcessor,com.google.auto.value.processor.AutoOneOfProcessor \
            -s generated -d classes @sources

          while IFS= read -r archive; do
            (cd runtime-classes; jar --extract --file "$archive")
          done < dependencies
          cp -a classes/. runtime-classes/
          cp ${bazelSource}/third_party/jarjar/java/com/tonicsystems/jarjar/help.txt \
            runtime-classes/com/tonicsystems/jarjar/
          rm -f runtime-classes/META-INF/MANIFEST.MF
          find runtime-classes/META-INF -type f \
            \( -name '*.SF' -o -name '*.RSA' -o -name '*.DSA' \) -delete

          mkdir -p "$out/java_tools"
          while read -r archive mainClass; do
            jar --create --file "$out/java_tools/$archive" \
              --main-class "$mainClass" --date=1980-01-01T00:00:02Z \
              -C runtime-classes .
          done <<'TOOLS'
          GenClass_deploy.jar com.google.devtools.build.buildjar.genclass.GenClass
          JavaBuilder_deploy.jar com.google.devtools.build.buildjar.BazelJavaBuilder
          VanillaJavaBuilder_deploy.jar com.google.devtools.build.buildjar.VanillaJavaBuilder
          turbine_direct_binary_deploy.jar com.google.turbine.main.Main
          Runner_deploy.jar com.google.testing.junit.runner.BazelTestRunner
          JacocoCoverage_deploy.jar com.google.testing.coverage.JacocoCoverageRunner
          TOOLS

          # Match upstream's coverage relocation using its checked-in rules.
          java -cp runtime-classes com.tonicsystems.jarjar.Main process \
            ${bazelSource}/src/java_tools/junitrunner/java/com/google/testing/coverage/JacocoCoverage.jarjar \
            "$out/java_tools/JacocoCoverage_deploy.jar" \
            "$out/java_tools/JacocoCoverage_jarjar_deploy.jar"

          python3 - ${bazelSource} "$out" <<'PY'
          from pathlib import Path
          import re
          import shutil
          import sys

          source, output = map(Path, sys.argv[1:])
          build = source / "tools/jdk/BUILD.java_tools"
          shutil.copyfile(build, output / "BUILD.bazel")
          for relative in sorted(set(re.findall(r'"(java_tools/[^"\n]+)"', build.read_text()))):
              if relative.endswith(".jar"):
                  continue
              original = relative.removeprefix("java_tools/")
              if original.startswith("ijar/"):
                  original = "third_party/" + original
              original_path = source / original
              if not original_path.is_file():
                  raise SystemExit(f"missing upstream Java tools source: {original}")
              destination = output / relative
              destination.parent.mkdir(parents=True, exist_ok=True)
              shutil.copyfile(original_path, destination)
          PY

          mkdir -p "$out/java_tools/third_party/java/jacoco" \
            "$out/java_tools/third_party/java/proguard"
          cp ${bazelJacoco}/share/java/*.jar "$out/java_tools/third_party/java/jacoco/"
          cp ${bazelAsm}/share/java/*-9.6.jar "$out/java_tools/third_party/java/jacoco/"
          ${asmSourceInstall}
          cp ${bazelProguard}/share/java/proguard-base-*.jar \
            "$out/java_tools/third_party/java/proguard/proguard.jar"
          touch "$out/WORKSPACE.bazel"
        '';
      }
    ];
  }
