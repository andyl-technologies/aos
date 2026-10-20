##! Netty common and its Graal compile-time annotations built from source.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelLog4j,
  bazelLegacyJavaHttp,
  bazelBlockHound,
  bazelByteBuddy,
  version ? "4.1.93.Final",
  sourceHash ? "sha256-k9qffGL04PABw9D+0OHqJ8NVVqbqcywHlsriSozuWbU=",
  osgiAnnotations ? null,
}: let
  buildJdk = buildPackages.openjdk-17;
  nettySource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-common/${version}/netty-common-${version}-sources.jar"];
    hash = sourceHash;
  };
  svmSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/oracle/substratevm/svm/19.3.6/svm-19.3.6-sources.jar"];
    hash = "sha256-XP0RQxeyYZ7ttg8/1Q7phc2HAkiHgm1/1mNC8XgeKyY=";
  };
in
  mkDerivation {
    pname = "bazel-netty-common";
    inherit version;
    src = nettySource;

    buildDeps =
      [
        buildJdk
        bazelMavenBootstrap
        bazelLog4j
        bazelLegacyJavaHttp
        bazelBlockHound
        bazelByteBuddy
        buildPackages.findutils
        buildPackages.python3
        buildPackages.unzip
      ]
      ++ (
        if osgiAnnotations == null
        then []
        else [osgiAnnotations]
      );
    runtimeDeps =
      if osgiAnnotations == null
      then []
      else [osgiAnnotations];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - ${nettySource} ${svmSource} <<'PY'
          import sys
          from zipfile import ZipFile

          compiled_suffixes = (
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          )
          for source_path in sys.argv[1:]:
              with ZipFile(source_path) as source:
                  for member in source.infolist():
                      if member.is_dir():
                          continue
                      if member.filename.lower().endswith(compiled_suffixes):
                          raise SystemExit(f"Compiled payload in {source_path}: {member.filename}")
                      if b"\0" in source.read(member):
                          raise SystemExit(f"Opaque payload in {source_path}: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p netty-source svm-source netty-classes svm-classes
          unzip -q ${nettySource} -d netty-source
          unzip -q ${svmSource} -d svm-source

          svmAnnotations=svm-source/com/oracle/svm/core/annotate
          javac --add-modules jdk.internal.vm.ci \
            --add-exports jdk.internal.vm.ci/jdk.vm.ci.meta=ALL-UNNAMED \
            -proc:none -encoding UTF-8 -d svm-classes \
            "$svmAnnotations/Alias.java" \
            "$svmAnnotations/InjectAccessors.java" \
            "$svmAnnotations/TargetClass.java" \
            "$svmAnnotations/RecomputeFieldValue.java"

          mavenClasspath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath:${bazelLog4j}/maven/log4j/log4j/1.2.17/log4j-1.2.17.jar"
          classpath="$classpath:${bazelLegacyJavaHttp}/maven/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"
          classpath="$classpath:${bazelBlockHound}/share/java/blockhound-1.0.6.RELEASE.jar"
          classpath="$classpath:${bazelByteBuddy}/share/java/byte-buddy-dep-1.10.22.jar"
          classpath="$classpath:${bazelByteBuddy}/share/java/byte-buddy-shaded-asm-1.10.22.jar:svm-classes"
          ${
            if osgiAnnotations == null
            then ""
            else ''
              classpath="$classpath:${osgiAnnotations}/maven/org/osgi/osgi.annotation/8.1.0/osgi.annotation-8.1.0.jar"
            ''
          }

          find netty-source/io -name '*.java' -print > netty-sources
          # Netty uses sun.misc.Unsafe; --release 8 hides that JDK API.
          javac -source 8 -target 8 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d netty-classes @netty-sources

          find netty-source -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              relative=''${resource#netty-source/}
              destination="netty-classes/$relative"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          jar --create --file "$out/share/java/netty-common-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C netty-classes .
          jar --create --file "$out/share/java/svm-annotations-19.3.6.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C svm-classes .
        '';
      }
    ];
  }
