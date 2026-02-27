##! ant-bootstrap — Apache Ant 1.8.4 bootstrapped with Jikes + JamVM
{
  mkDerivation,
  fetchurl,
  gnumake,
  jikes,
  jamvm-1_5,
  classpath-0_93,
}: let
  version = "1.8.4";
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

    buildDeps = [gnumake jikes jamvm-1_5 classpath-0_93];
    runtimeDeps = [jamvm-1_5 classpath-0_93];

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
          export JAVA_HOME=${jamvm-1_5}
          export JAVAC="${jikes}/bin/jikes -bootclasspath ${classpath-0_93}/share/classpath/glibj.zip"
          export ANT_HOME=$out
          $CONFIG_SHELL bootstrap.sh
        '';
      }
      {
        name = "install";
        script = ''
                  mkdir -p $out/bin $out/lib
                  cp -r bootstrap/lib/* $out/lib/
                  cp bootstrap/bin/ant $out/bin/
                  chmod +x $out/bin/ant

                  # Create a wrapper that sets up the classpath and JVM correctly
                  mv $out/bin/ant $out/bin/.ant-unwrapped
                  cat > $out/bin/ant <<WRAPPER
          #!/bin/sh
          export JAVA_HOME="${jamvm-1_5}"
          export ANT_HOME="$out"
          export CLASSPATH="$out/lib/ant.jar:$out/lib/ant-launcher.jar"
          exec $out/bin/.ant-unwrapped "\$@"
          WRAPPER
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
