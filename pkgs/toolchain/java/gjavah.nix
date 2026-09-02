##! gjavah — GNU Classpath Java header generator (JNI)
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  ecj-bootstrap,
  fastjar,
  jamvm-1_5,
  jamvm-2_0,
  classpath-0_99,
}: let
  version = "0.99";
  ecjForBuild =
    if stdenv.isCross
    then buildPackages.ecj-bootstrap
    else ecj-bootstrap;
  fastjarForBuild =
    if stdenv.isCross
    then buildPackages.fastjar
    else fastjar;
  jamvmForBuild =
    if stdenv.isCross
    then buildPackages.jamvm-1_5
    else jamvm-1_5;
  classpathSrc = fetchurl {
    urls = [
      "https://mirrors.kernel.org/gnu/classpath/classpath-${version}.tar.gz"
    ];
    hash = "sha256-+Skpf4rpthOhoWfiMVZoYYkyYGUdkTrZtsEZM4lf7Mg=";
  };
in
  mkDerivation {
    pname = "gjavah";
    inherit version;

    src = classpathSrc;

    buildDeps = [
      ecjForBuild
      fastjarForBuild
      jamvmForBuild
      classpath-0_99
    ];
    runtimeDeps = [
      jamvm-2_0
      classpath-0_99
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd classpath-${version}/tools
        '';
      }
      {
        name = "patch";
        script = ''
          # Remove ASM Type.java methods that reference java.lang.reflect.Method
          sed -i '/import java\.lang\.reflect\.Method/d' \
            external/asm/org/objectweb/asm/Type.java
          sed -i '/public static Type\[\] getArgumentTypes(final Method/,/^    }/d' \
            external/asm/org/objectweb/asm/Type.java
          sed -i '/public static Type getReturnType(final Method/,/^    }/d' \
            external/asm/org/objectweb/asm/Type.java
          sed -i '/public static String getMethodDescriptor(final Method/,/^    }/d' \
            external/asm/org/objectweb/asm/Type.java
        '';
      }
      {
        name = "build";
        script = ''
          GLIBJ=${classpath-0_99}/share/classpath/glibj.zip
          CLASSES=$PWD/classes
          mkdir -p $CLASSES/gnu/classpath/tools $CLASSES/org/objectweb/asm

          # Find ASM core classes (exclude xml subdir)
          find external/asm/org/objectweb/asm -name '*.java' \
            ! -path '*/xml/*' > /tmp/javah-sources.txt

          # Add getopt utilities and ClasspathToolParser + Messages from common
          find gnu/classpath/tools/getopt -name '*.java' >> /tmp/javah-sources.txt
          echo gnu/classpath/tools/common/ClasspathToolParser.java >> /tmp/javah-sources.txt
          echo gnu/classpath/tools/common/Messages.java >> /tmp/javah-sources.txt

          # Add the javah sources
          find gnu/classpath/tools/javah -name '*.java' >> /tmp/javah-sources.txt

          ${ecjForBuild}/bin/ecj \
            -source 1.5 -target 1.5 \
            -encoding UTF-8 \
            -bootclasspath $GLIBJ \
            -classpath external/asm \
            -d $CLASSES \
            -nowarn \
            @/tmp/javah-sources.txt

          # Copy resource bundles needed at runtime (messages.properties etc.)
          if [ -d resource ]; then
            (cd resource && find . -type f | while read f; do
              d=$(dirname "$f")
              mkdir -p "$CLASSES/$d"
              cp "$f" "$CLASSES/$f"
            done)
          fi
        '';
      }
      {
        name = "install";
        script = ''
          GLIBJ=${classpath-0_99}/share/classpath/glibj.zip

          # Create tools.zip
          mkdir -p $out/lib $out/bin
          cd $PWD/classes
          ${fastjarForBuild}/bin/fastjar cf $out/lib/tools.zip .

          # Create gjavah wrapper using JamVM 2.0 (which uses classpath-0.99)
          printf '#!/bin/sh\nexec %s -cp %s gnu.classpath.tools.javah.Main "$@"\n' \
            "${jamvm-2_0}/bin/jamvm" \
            "$out/lib/tools.zip" \
            > $out/bin/gjavah
          chmod +x $out/bin/gjavah
        '';
      }
    ];

    meta = {
      description = "GNU Classpath gjavah — Java header generator for JNI";
      homepage = "https://www.gnu.org/software/classpath/";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
