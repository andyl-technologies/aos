##! ant-bootstrap — Apache Ant 1.8.4 bootstrapped with Jikes + JamVM
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  jikes,
  fastjar,
  jamvm-1_5,
  classpath-0_93,
}: let
  version = "1.8.4";
  jikesForBuild =
    if stdenv.isCross
    then buildPackages.jikes
    else jikes;
  fastjarForBuild =
    if stdenv.isCross
    then buildPackages.fastjar
    else fastjar;
in
  mkDerivation {
    pname = "ant-bootstrap";
    inherit version;

    src = fetchurl {
      urls = [
        "https://archive.apache.org/dist/ant/source/apache-ant-${version}-src.tar.bz2"
      ];
      hash = "sha256-XeZfe6P2fkNv//zcCnP1kdEAbp+0GvhjLB8fhNSj4LE=";
    };

    buildDeps = [
      gnumake
      jikesForBuild
      fastjarForBuild
      jamvm-1_5
      classpath-0_93
    ];
    runtimeDeps = [
      jamvm-1_5
      classpath-0_93
    ];

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
          TOOLS=src/main/org/apache/tools
          CLASSDIR=build/classes
          mkdir -p build $CLASSDIR

          # Resolve version.txt placeholders
          printf 'VERSION=%s\nDATE=%s\n' "${version}" "2012-05-02" \
            > $TOOLS/ant/version.txt

          # Compile the bootstrap subset (exact same files as bootstrap.sh)
          ${jikesForBuild}/bin/jikes \
            -bootclasspath ${classpath-0_93}/share/classpath/glibj.zip \
            -sourcepath src/main \
            -d $CLASSDIR -nowarn \
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

          # Copy resources (properties, version, etc.)
          cd src/main
          find . -type f \( -name '*.properties' -o -name '*.txt' -o -name '*.dtd' -o -name '*.xml' -o -name '*.mf' \) | while read f; do
            dir=$(dirname "$f")
            mkdir -p "../../$CLASSDIR/$dir"
            cp "$f" "../../$CLASSDIR/$f"
          done
          cd ../..

          # Create jars
          mkdir -p bootstrap/lib
          cd $CLASSDIR
          ${fastjarForBuild}/bin/fastjar cf ../../bootstrap/lib/ant.jar .
          ${fastjarForBuild}/bin/fastjar cf ../../bootstrap/lib/ant-launcher.jar \
            org/apache/tools/ant/launch
          cd ../..
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/lib $out/jre/bin
          cp bootstrap/lib/*.jar $out/lib/
          ln -s ${jamvm-1_5}/bin/jamvm $out/jre/bin/java

          # Create ant wrapper
          printf '#!/bin/sh\nexport JAVA_HOME="%s/jre"\nexport ANT_HOME="%s"\nexport CLASSPATH="%s/lib/ant.jar:%s/lib/ant-launcher.jar"\nexec %s/jre/bin/java -cp "$CLASSPATH" org.apache.tools.ant.launch.Launcher "$@"\n' \
            "$out" "$out" "$out" "$out" "$out" \
            > $out/bin/ant
          chmod +x $out/bin/ant
        '';
      }
    ];

    meta = {
      description = "Apache Ant 1.8.4 — build tool bootstrapped with Jikes + JamVM";
      homepage = "https://ant.apache.org/";
      license = "Apache-2.0";
    };
  }
