##! Source-built Java libraries used by Bazel's bootstrap classpath.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  archives = [
    {
      target = "com/beust/jcommander/1.82/jcommander-1.82.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/beust/jcommander/1.82/jcommander-1.82-sources.jar";
      hash = "sha256-zDnSLzzynCAz+1JuVgCuj+w24xYnSwwH+hTBpKOOyjs=";
    }
    {
      target = "com/github/stephenc/jcip/jcip-annotations/1.0-1/jcip-annotations-1.0-1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/github/stephenc/jcip/jcip-annotations/1.0-1/jcip-annotations-1.0-1-sources.jar";
      hash = "sha256-1guzv04DpeQF+bFvTCYl3oYInWzk+Zm8wlSNysCQrhk=";
    }
    {
      target = "com/google/android/annotations/4.1.1.4/annotations-4.1.1.4.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/android/annotations/4.1.1.4/annotations-4.1.1.4-sources.jar";
      hash = "sha256-6bZnqpWN946hrRFfe7rBilhpwxKLHVBD/rNgsM/OnUA=";
    }
    {
      target = "com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2-sources.jar";
      hash = "sha256-HJ6F4nLQcIxqWR3HSCjHFgMFO0jMda6DzOVpEqKqBjs=";
    }
    {
      target = "com/google/errorprone/error_prone_annotations/2.36.0/error_prone_annotations-2.36.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_annotations/2.36.0/error_prone_annotations-2.36.0-sources.jar";
      hash = "sha256-fhF+CTHLLLQiY3KvM2GJtJ7beZadEg7JWKbfC+rLBhI=";
    }
    {
      target = "com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1-sources.jar";
      hash = "sha256-CSNG7ruxZXtRqnSFoka/YCu0ZMwLDi4cfnIB+tzh6Y8=";
    }
    {
      target = "com/google/j2objc/j2objc-annotations/2.8/j2objc-annotations-2.8.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/j2objc/j2objc-annotations/2.8/j2objc-annotations-2.8-sources.jar";
      hash = "sha256-dBPu1B8RFFOgiDf1rGgO3e1/rtRmy9NXReQC4T9Mw/U=";
    }
    {
      target = "org/checkerframework/checker-qual/3.37.0/checker-qual-3.37.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/checkerframework/checker-qual/3.37.0/checker-qual-3.37.0-sources.jar";
      hash = "sha256-LKMcfpWa2C/icLK6rBGlnFcPh3gZEjPFSSfpStq3tkA=";
    }
    {
      target = "org/checkerframework/checker-compat-qual/2.5.3/checker-compat-qual-2.5.3.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/checkerframework/checker-compat-qual/2.5.3/checker-compat-qual-2.5.3-sources.jar";
      hash = "sha256-aAEXc/1gz8d3JQgTQIZ4chC6KhRD4/nD9dQjOiJsM0Y=";
    }
    {
      target = "com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre-sources.jar";
      hash = "sha256-n28zOy3q82ZE0U3e7X5rMRUbDCRLqx5NWO5EOt6aCfM=";
    }
    {
      target = "com/google/errorprone/error_prone_annotation/2.36.0/error_prone_annotation-2.36.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_annotation/2.36.0/error_prone_annotation-2.36.0-sources.jar";
      hash = "sha256-+KJhtX9nGhGRBh4QfMJRdbaJwXKrkdMREF3AD6eMrKI=";
    }
    {
      target = "com/google/code/gson/gson/2.9.0/gson-2.9.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/code/gson/gson/2.9.0/gson-2.9.0-sources.jar";
      hash = "sha256-dUKURunZ6QxbaoSqBtjSd4PynHCz3mWmwtUNJ87OZNw=";
    }
    {
      target = "com/google/auto/service/auto-service-annotations/1.0.1/auto-service-annotations-1.0.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/auto/service/auto-service-annotations/1.0.1/auto-service-annotations-1.0.1-sources.jar";
      hash = "sha256-sBPKFZsP6joAQdPV+7O35JqBnagKFyoB+xfdKP2Y5ys=";
    }
    {
      target = "com/squareup/javapoet/1.12.0/javapoet-1.12.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/squareup/javapoet/1.12.0/javapoet-1.12.0-sources.jar";
      hash = "sha256-qjS+tZiJcPKAXi+RUR3TeBzMPUAV8Q6euU952PcTUwI=";
    }
    {
      target = "commons-codec/commons-codec/1.16.1/commons-codec-1.16.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/commons-codec/commons-codec/1.16.1/commons-codec-1.16.1-sources.jar";
      hash = "sha256-G51zNr75UM1F2+/VNRIi7ojk794JqUVOhRpFjDT4E74=";
    }
    {
      target = "commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2-sources.jar";
      hash = "sha256-pbXuFqAu2t9/5jfyUCF8GYeLxhNPFetVY1xImW9v7R0=";
      # Map.remove(Object, Object) gained an incompatible Java 8 default method.
      javaRelease = 7;
    }
    {
      target = "commons-io/commons-io/2.15.1/commons-io-2.15.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/commons-io/commons-io/2.15.1/commons-io-2.15.1-sources.jar";
      hash = "sha256-UMsku4PB7cscEAektsfqAkxxrA+gGLgKVzkdfHtbgkY=";
    }
    {
      target = "io/github/java-diff-utils/java-diff-utils/4.12/java-diff-utils-4.12.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/io/github/java-diff-utils/java-diff-utils/4.12/java-diff-utils-4.12-sources.jar";
      hash = "sha256-+iQhe26qEVoF1KjwAD/pE8YnFsohhNLk8X3kp9QqiCI=";
    }
  ];

  sources = builtins.genList (
    index: let
      archive = builtins.elemAt archives index;
    in
      archive
      // {
        inherit index;
        src = fetchurl {
          urls = [archive.sourceUrl];
          inherit (archive) hash;
        };
      }
  ) (builtins.length archives);

  unpackSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p source-${toString source.index}
      unzip -q ${source.src} -d source-${toString source.index}
      if test -n "$(find source-${toString source.index} -type f \
          \( -name '*.class' -o -name '*.so' -o -name '*.dylib' \
          -o -name '*.dll' -o -name '*.a' \) -print -quit)"; then
        echo "Compiled payload in ${source.target} source archive" >&2
        exit 1
      fi
    '')
    sources);

  buildJars = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p classes-${toString source.index}
      find source-${toString source.index} -type f -name '*.java' \
        ! -name module-info.java -print > sources-${toString source.index}.list
      test -s sources-${toString source.index}.list
      javac --release ${toString (source.javaRelease or 17)} -encoding UTF-8 -proc:none \
        -cp ".''${classpath:+:$classpath}" -d classes-${toString source.index} \
        @sources-${toString source.index}.list
      jar --create --file jar-${toString source.index}.jar --no-manifest \
        --date=1980-01-01T00:00:02Z -C classes-${toString source.index} .
      classpath="classes-${toString source.index}''${classpath:+:$classpath}"
    '')
    sources);

  installJars = builtins.concatStringsSep "\n" (builtins.map (source: ''
      install -Dm644 jar-${toString source.index}.jar \
        "$out/maven/${source.target}"
    '')
    sources);

  buildJdk = buildPackages.openjdk-17;
in
  mkDerivation {
    pname = "bazel-maven-bootstrap";
    version = "7.7.1";
    src = (builtins.head sources).src;

    buildDeps = [
      buildJdk
      buildPackages.unzip
      buildPackages.findutils
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = unpackSources;
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME="${buildJdk}"
          export PATH="${buildJdk}/bin:$PATH"
          classpath=
          ${buildJars}
        '';
      }
      {
        name = "install";
        script = installJars;
      }
    ];

    meta = {
      description = "Bazel bootstrap Maven libraries built from Java source";
      license = "mixed";
    };
  }
