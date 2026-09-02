##! tla-plus — TLA+ tools: TLC model checker, SANY parser, PlusCal translator
{
  mkDerivation,
  fetchurl,
  buildPackages,
  openjdk-17,
}: let
  version = "1.7.4";
  jdk = openjdk-17;
  buildJdk = buildPackages.openjdk-17;
  buildAnt = buildPackages.ant;
  buildBash = buildPackages.bash;
in
  mkDerivation {
    pname = "tla-plus";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/tlaplus/tlaplus/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-605UtsjcSUXL1pfb/lWBm2/D8T/pVhr9fWUjwY6kw1A=";
    };

    buildDeps = [
      buildJdk
      buildAnt
      buildBash
    ];
    runtimeDeps = [jdk];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tlaplus-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME="${buildJdk}"
          export PATH="${buildJdk}/bin:${buildAnt}/bin:$PATH"

          cd tlatools/org.lamport.tlatools

          # Generate parser from JavaCC grammar
          # JavaCC 4.0 is bundled in lib/
          if test -f lib/javacc-4.0.jar; then
            mkdir -p src/tla2sany/parser
            java -cp lib/javacc-4.0.jar javacc \
              -OUTPUT_DIRECTORY=src/tla2sany/parser \
              javacc/tla+.jj 2>&1 || true
          fi

          # Build tla2tools.jar using Ant
          ant -f customBuild.xml compile 2>&1
          ant -f customBuild.xml dist 2>&1
        '';
      }
      {
        name = "install";
        script = ''
                  mkdir -p $out/bin $out/lib $out/share/tla-plus

                  # Install the built jar
                  if test -f dist/tla2tools.jar; then
                    cp dist/tla2tools.jar $out/lib/
                  elif test -f tla2tools.jar; then
                    cp tla2tools.jar $out/lib/
                  else
                    # Find wherever the jar ended up
                    found=$(find . -name 'tla2tools.jar' -type f | head -1)
                    if test -n "$found"; then
                      cp "$found" $out/lib/
                    else
                      echo "ERROR: tla2tools.jar not found"
                      exit 1
                    fi
                  fi

                  # Create wrapper scripts
                  cat > $out/bin/tlc << 'WRAPPER'
          #!/bin/sh
          exec JAVA_BIN -XX:+UseParallelGC -cp JAR_PATH tlc2.TLC "$@"
          WRAPPER
                  sed -i "s|JAVA_BIN|${jdk}/bin/java|;s|JAR_PATH|$out/lib/tla2tools.jar|" $out/bin/tlc
                  chmod +x $out/bin/tlc

                  cat > $out/bin/sany << 'WRAPPER'
          #!/bin/sh
          exec JAVA_BIN -cp JAR_PATH tla2sany.SANY "$@"
          WRAPPER
                  sed -i "s|JAVA_BIN|${jdk}/bin/java|;s|JAR_PATH|$out/lib/tla2tools.jar|" $out/bin/sany
                  chmod +x $out/bin/sany

                  cat > $out/bin/pcal << 'WRAPPER'
          #!/bin/sh
          exec JAVA_BIN -cp JAR_PATH pcal.trans "$@"
          WRAPPER
                  sed -i "s|JAVA_BIN|${jdk}/bin/java|;s|JAR_PATH|$out/lib/tla2tools.jar|" $out/bin/pcal
                  chmod +x $out/bin/pcal

                  cat > $out/bin/tlatex << 'WRAPPER'
          #!/bin/sh
          exec JAVA_BIN -cp JAR_PATH tla2tex.TLA "$@"
          WRAPPER
                  sed -i "s|JAVA_BIN|${jdk}/bin/java|;s|JAR_PATH|$out/lib/tla2tools.jar|" $out/bin/tlatex
                  chmod +x $out/bin/tlatex
        '';
      }
    ];

    meta = {
      description = "TLA+ tools — TLC model checker, SANY parser, PlusCal translator";
      homepage = "https://lamport.azurewebsites.net/tla/tools.html";
      license = "MIT";
    };
  }
