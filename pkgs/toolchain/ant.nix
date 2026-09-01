##! ant — Apache Ant build tool, bootstrapped from source with OpenJDK 17
{
  mkDerivation,
  fetchurl,
  buildPackages,
  openjdk-17,
}: let
  version = "1.10.15";
  jdk = openjdk-17;
  buildJdk = buildPackages.openjdk-17;
  buildBash = buildPackages.bash;
in
  mkDerivation {
    pname = "ant";
    inherit version;

    src = fetchurl {
      urls = [
        "https://archive.apache.org/dist/ant/source/apache-ant-${version}-src.tar.gz"
      ];
      hash = "sha256-oitJW5wFSChB+RnTRA0rOCE64iPgOYWbc6q83kRBmbE=";
    };

    buildDeps = [
      buildJdk
      buildBash
    ];
    runtimeDeps = [jdk];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd apache-ant-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME="${buildJdk}"
          export PATH="${buildJdk}/bin:$PATH"

          # Follow upstream bootstrap.sh: compile only the core subset that
          # has no external dependencies, then use that to build the rest.
          TOOLS=src/main/org/apache/tools
          CLASSDIR=build/classes

          mkdir -p build $CLASSDIR bin

          # Compile core bootstrap classes (exact list from bootstrap.sh)
          # -sourcepath lets javac resolve transitive deps from the source tree
          javac -proc:none -sourcepath src/main -d $CLASSDIR \
            $TOOLS/bzip2/*.java \
            $TOOLS/tar/*.java \
            $TOOLS/zip/*.java \
            $TOOLS/ant/util/regexp/RegexpMatcher.java \
            $TOOLS/ant/util/regexp/RegexpMatcherFactory.java \
            $TOOLS/ant/property/*.java \
            $TOOLS/ant/types/*.java \
            $TOOLS/ant/types/resources/*.java \
            $TOOLS/ant/*.java \
            $TOOLS/ant/taskdefs/*.java \
            $TOOLS/ant/taskdefs/compilers/*.java \
            $TOOLS/ant/taskdefs/condition/*.java

          # Copy required property files
          cp src/main/org/apache/tools/ant/taskdefs/defaults.properties \
            $CLASSDIR/org/apache/tools/ant/taskdefs/
          cp src/main/org/apache/tools/ant/types/defaults.properties \
            $CLASSDIR/org/apache/tools/ant/types/

          # Create antRun helper
          cp src/script/antRun bin/
          chmod +x bin/antRun

          # Use bootstrapped classes to run ant bootstrap target
          export CLASSPATH="$CLASSDIR:src/main"
          java -Dant.home=. org.apache.tools.ant.Main -emacs bootstrap
        '';
      }
      {
        name = "install";
        script = ''
                  mkdir -p $out/bin $out/lib

                  # bootstrap/ contains the fully-built Ant distribution
                  cp bootstrap/lib/*.jar $out/lib/

                  # Create ant wrapper script
                  cat > $out/bin/ant << 'WRAPPER'
          #!/bin/sh
          export JAVA_HOME="JDK_PATH"
          export ANT_HOME="ANT_HOME_PATH"
          exec "JDK_PATH/bin/java" -cp "ANT_HOME_PATH/lib/ant-launcher.jar" org.apache.tools.ant.launch.Launcher "$@"
          WRAPPER
                  sed -i "s|JDK_PATH|${jdk}|g;s|ANT_HOME_PATH|$out|g" $out/bin/ant
                  chmod +x $out/bin/ant
        '';
      }
    ];

    meta = {
      description = "Apache Ant — Java-based build tool";
      homepage = "https://ant.apache.org/";
      license = "Apache-2.0";
    };
  }
