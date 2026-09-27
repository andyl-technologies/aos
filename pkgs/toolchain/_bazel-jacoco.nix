##! JaCoCo coverage JARs compiled from the pinned upstream source tree.
{
  mkDerivation,
  buildPackages,
  bazelAsm,
  bazelJacocoSource,
}: let
  version = "0.8.11";
  jdk = buildPackages.openjdk-21;
  asmJars = builtins.map (component: "${bazelAsm}/share/java/${component}-9.6.jar") [
    "asm"
    "asm-tree"
    "asm-analysis"
    "asm-commons"
    "asm-util"
  ];
  asmClasspath = builtins.concatStringsSep ":" asmJars;
in
  mkDerivation {
    pname = "bazel-jacoco";
    inherit version;
    src = bazelJacocoSource;

    buildDeps = [jdk buildPackages.findutils buildPackages.grep buildPackages.patch bazelAsm];
    runtimeDeps = [bazelAsm];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
          patch --batch --fuzz=0 -p1 < ${./bazel-jacoco-patches/0001-exclude-agent-archive.patch}
          cd ..
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p core-classes report-classes agent-rt-classes agent-classes

          for component in core report agent.rt agent; do
            find "source/org.jacoco.$component/src" -name '*.java' -type f \
              | sort > "$component-sources"
          done

          ${jdk}/bin/javac --release 8 -Xlint:-options -proc:none \
            -cp '${asmClasspath}' -d core-classes @core-sources
          ${jdk}/bin/javac --release 8 -Xlint:-options -proc:none \
            -cp "core-classes:${asmClasspath}" \
            -d report-classes @report-sources
          ${jdk}/bin/javac --release 8 -Xlint:-options -proc:none \
            -cp "core-classes:${asmClasspath}" \
            -d agent-rt-classes @agent.rt-sources
          ${jdk}/bin/javac --release 8 -Xlint:-options -proc:none \
            -d agent-classes @agent-sources

          build_root=$PWD
          for component in core report agent.rt; do
            case "$component" in
              core) destination=core-classes ;;
              report) destination=report-classes ;;
              agent.rt) destination=agent-rt-classes ;;
            esac
            (cd "source/org.jacoco.$component/src"; \
              find . -type f ! -name '*.java' -exec cp --parents '{}' \
                "$build_root/$destination" \;)
          done

          cat > core-classes/org/jacoco/core/jacoco.properties <<'PROPERTIES'
          VERSION=${version}
          COMMITID=f33756c37f1e41041d84018047b14cb394742761
          HOMEURL=https://www.jacoco.org/jacoco/
          RUNTIMEPACKAGE=org.jacoco.agent.rt.internal
          PROPERTIES

          mkdir -p agent-runtime-bundle
          cp -R core-classes/. agent-runtime-bundle/
          cp -R agent-rt-classes/. agent-runtime-bundle/
          for archive in ${builtins.concatStringsSep " " asmJars}; do
            (cd agent-runtime-bundle; ${jdk}/bin/jar --extract --file "$archive")
          done
          rm -rf agent-runtime-bundle/META-INF

          cat > agent-manifest <<'MANIFEST'
          Manifest-Version: 1.0
          Premain-Class: org.jacoco.agent.rt.internal.PreMain
          Agent-Class: org.jacoco.agent.rt.internal.PreMain
          Can-Redefine-Classes: true
          Can-Retransform-Classes: true

          MANIFEST

          ${jdk}/bin/jar --create --date=1980-01-01T00:00:02Z \
            --file jacocoagent-${version}.jar --manifest agent-manifest \
            -C agent-runtime-bundle .
          cp jacocoagent-${version}.jar agent-classes/jacocoagent.jar
        '';
      }
      {
        name = "check";
        script = ''
          cat > CoverageSmoke.java <<'JAVA'
          final class CoverageSmoke {
              public static void main(String[] args) {
                  if (args.length != 1) throw new AssertionError("missing argument");
                  System.out.println(args[0]);
              }
          }
          JAVA
          ${jdk}/bin/javac --release 8 -Xlint:-options -proc:none CoverageSmoke.java
          ${jdk}/bin/java -javaagent:jacocoagent-${version}.jar=output=file,destfile=coverage.exec \
            CoverageSmoke source-built
          test -s coverage.exec
          grep -a -q CoverageSmoke coverage.exec
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/share/java"
          mkdir -p "$destination" "$out/share/licenses/jacoco"

          for component in core report agent; do
            classes="$component-classes"
            ${jdk}/bin/jar --create --date=1980-01-01T00:00:02Z \
              --file "$destination/org.jacoco.$component-${version}.jar" \
              --no-manifest -C "$classes" .
            ${jdk}/bin/jar --create --date=1980-01-01T00:00:02Z \
              --file "$destination/org.jacoco.$component-${version}-sources.jar" \
              --no-manifest -C "source/org.jacoco.$component/src" .
          done

          cp jacocoagent-${version}.jar "$destination/"
          cp source/LICENSE.md "$out/share/licenses/jacoco/"
        '';
      }
    ];

    meta = {
      description = "JaCoCo coverage libraries and agent built from source for Bazel";
      homepage = "https://www.jacoco.org/jacoco/";
      license = "EPL-2.0";
    };
  }
