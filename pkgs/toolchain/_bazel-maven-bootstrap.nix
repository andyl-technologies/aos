##! Source-built Java libraries used by Bazel's bootstrap classpath.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  bazelAsm = import ./_bazel-asm.nix {
    inherit mkDerivation fetchurl buildPackages;
  };

  cglibBuildClasspath = builtins.concatStringsSep ":" [
    "${bazelAsm}/share/java/asm-9.2.jar"
    "${bazelAsm}/share/java/asm-tree-9.2.jar"
    "${bazelAsm}/share/java/asm-analysis-9.2.jar"
    "${bazelAsm}/share/java/asm-commons-9.2.jar"
    "${bazelAsm}/share/java/asm-util-9.2.jar"
    "${buildPackages.ant}/lib/ant.jar"
  ];

  extraClasspath = source:
    if source ? extraClasspath
    then ":${source.extraClasspath}"
    else "";

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
      target = "commons-lang/commons-lang/2.6/commons-lang-2.6.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/commons-lang/commons-lang/2.6/commons-lang-2.6-sources.jar";
      hash = "sha256-ZsJ2CUXOwibyYobd8/b/44VExKaareiXAKmmicm5I4A=";
      javaRelease = 7;
      sourceEncoding = "ISO-8859-1";
      legacyEnumPackage = true;
    }
    {
      target = "io/github/java-diff-utils/java-diff-utils/4.12/java-diff-utils-4.12.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/io/github/java-diff-utils/java-diff-utils/4.12/java-diff-utils-4.12-sources.jar";
      hash = "sha256-+iQhe26qEVoF1KjwAD/pE8YnFsohhNLk8X3kp9QqiCI=";
    }
    {
      target = "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0-sources.jar";
      hash = "sha256-qzuGr7iY8QJtvkOq9x6cHXGexS1uQYh7Ni2Gd3wpm28=";
    }
    {
      target = "org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1-sources.jar";
      hash = "sha256-4v+Fo8Ng1WxRpwIWFKGU8/uvIkBUZCrFNQFvEYMik00=";
    }
    {
      target = "com/google/errorprone/error_prone_type_annotations/2.36.0/error_prone_type_annotations-2.36.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_type_annotations/2.36.0/error_prone_type_annotations-2.36.0-sources.jar";
      hash = "sha256-y46Yv+vDM/W2KUgno5jFw/Je+i0y8iNA067xNBGtrw0=";
    }
    {
      target = "com/google/auto/value/auto-value-annotations/1.11.0/auto-value-annotations-1.11.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/auto/value/auto-value-annotations/1.11.0/auto-value-annotations-1.11.0-sources.jar";
      hash = "sha256-15QeXxm7OK/PqFNQ1X5SRYVsI8mMK74y9tMbVXfyvDM=";
      # The source classifier also carries the separately packaged processor.
      javaRoot = "com/google/auto/value";
      javaMaxDepth = 1;
      copyResources = false;
    }
    {
      target = "com/google/flogger/flogger/0.5.1/flogger-0.5.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/flogger/flogger/0.5.1/flogger-0.5.1-sources.jar";
      hash = "sha256-jfRkg0oz1MJw4OdoEMeTqoGsp8PIhGMDIARxs3E4bwk=";
      compileOnlyPlatformProvider = true;
    }
    {
      target = "com/google/flogger/flogger-system-backend/0.5.1/flogger-system-backend-0.5.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/flogger/flogger-system-backend/0.5.1/flogger-system-backend-0.5.1-sources.jar";
      hash = "sha256-vWwRKMAz+of493O6Ae6F7fmiIQEIIttiVF7W7A4l87E=";
    }
    {
      target = "com/google/flogger/google-extensions/0.5.1/google-extensions-0.5.1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/google/flogger/google-extensions/0.5.1/google-extensions-0.5.1-sources.jar";
      hash = "sha256-9ueEHdrrdQcWHStz15saRog+Lv8AEfUlxgCCUD9RTb8=";
    }
    {
      target = "com/github/ben-manes/caffeine/caffeine/3.0.5/caffeine-3.0.5.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/com/github/ben-manes/caffeine/caffeine/3.0.5/caffeine-3.0.5-sources.jar";
      hash = "sha256-LMqNHN/fM8HQ7sAhTNxtk/+KlRNr95hGWxClkkppvGU=";
    }
    {
      target = "org/jspecify/jspecify/1.0.0/jspecify-1.0.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/jspecify/jspecify/1.0.0/jspecify-1.0.0-sources.jar";
      hash = "sha256-rfCJgZHVWTf7MZK6lxgm9PKUKSxKlgdA88JzEOe3ApY=";
    }
    {
      target = "org/jetbrains/annotations/24.0.0/annotations-24.0.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/jetbrains/annotations/24.0.0/annotations-24.0.0-sources.jar";
      hash = "sha256-AHE2gb+W3YVXkCc1IPesGDzPeOyKmOuviRuiy9FK/uw=";
    }
    {
      target = "org/codehaus/mojo/animal-sniffer-annotations/1.21/animal-sniffer-annotations-1.21.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/codehaus/mojo/animal-sniffer-annotations/1.21/animal-sniffer-annotations-1.21-sources.jar";
      hash = "sha256-uWwOPpZobkrOkfQW/y98WlOlPyW+bkBPxxv88g6cJT4=";
    }
    {
      target = "org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3-sources.jar";
      hash = "sha256-4iPS2Puv1mBXqISMyUIi1jw87dZSzEjt3Aq1w5wPhN8=";
      javaRelease = 8;
      repairHamcrestGenerics = true;
    }
    {
      target = "junit/junit/4.13.2/junit-4.13.2.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/junit/junit/4.13.2/junit-4.13.2-sources.jar";
      hash = "sha256-NBgd9kgtQOpMBGsGPLU8f/rpS98bHWJpW986353qfjo=";
    }
    {
      target = "javax/inject/javax.inject/1/javax.inject-1.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/javax/inject/javax.inject/1/javax.inject-1-sources.jar";
      hash = "sha256-xLh+4pEcE5w9r0mKeBln8esudbwahSmi57MooV0OQz4=";
    }
    {
      target = "javax/annotation/javax.annotation-api/1.3.2/javax.annotation-api-1.3.2.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/javax/annotation/javax.annotation-api/1.3.2/javax.annotation-api-1.3.2-sources.jar";
      hash = "sha256-Eolx5S4NhKZuO24EnauK17LFi34a03+i3r09QMKUe5U=";
    }
    {
      target = "javax/activation/javax.activation-api/1.2.0/javax.activation-api-1.2.0.jar";
      # The API source archive omits its com.sun.activation.registries
      # implementation. The matching implementation source includes both.
      sourceUrl = "https://repo.maven.apache.org/maven2/com/sun/activation/javax.activation/1.2.0/javax.activation-1.2.0-sources.jar";
      hash = "sha256-flrtDMNUaE8clqHSRRPJXwlxVBue0Dv5CngroYlXECI=";
    }
    {
      target = "org/apache/tomcat/tomcat-annotations-api/8.0.5/tomcat-annotations-api-8.0.5.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/apache/tomcat/tomcat-annotations-api/8.0.5/tomcat-annotations-api-8.0.5-sources.jar";
      hash = "sha256-2zec4n56T9VpoajiY0xtXw8WxTYq67MIa/DmGUW/aCU=";
    }
    {
      target = "org/pcollections/pcollections/3.1.4/pcollections-3.1.4.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/pcollections/pcollections/3.1.4/pcollections-3.1.4-sources.jar";
      hash = "sha256-ONkbkUZ97c7f02trX1dwCP1RdIznQVDr4R7BInrM4hg=";
    }
    {
      target = "org/tukaani/xz/1.9/xz-1.9.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/tukaani/xz/1.9/xz-1.9-sources.jar";
      hash = "sha256-W++kfwa5DnUvA1GR3efy3rWfNgAPHKbMd9I2KoK29GI=";
    }
    {
      target = "org/yaml/snakeyaml/1.28/snakeyaml-1.28.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/yaml/snakeyaml/1.28/snakeyaml-1.28-sources.jar";
      hash = "sha256-cMo8et/pHjWdZs5kVt39eaf1Biutgzr3+Qo8w6LtIO0=";
    }
    {
      target = "cglib/cglib/3.3.0/cglib-3.3.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/cglib/cglib/3.3.0/cglib-3.3.0-sources.jar";
      hash = "sha256-ePx4qw1nvRmHVEPT4ZfgWeu+8q///YmMq4Er4m/28XY=";
      javaRelease = 8;
      extraClasspath = cglibBuildClasspath;
    }
    {
      target = "org/apache/commons/commons-pool2/2.8.0/commons-pool2-2.8.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/apache/commons/commons-pool2/2.8.0/commons-pool2-2.8.0-sources.jar";
      hash = "sha256-ZunMz3RYJWx2Y6JE3t3R09Q7JEXqgmccwxSlD/78oKo=";
    }
    {
      target = "org/joda/joda-convert/2.2.0/joda-convert-2.2.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/joda/joda-convert/2.2.0/joda-convert-2.2.0-sources.jar";
      hash = "sha256-o5tNdUBsTUWZfI1ckIJykqWNpRp/scyAnpwDRCojPtw=";
    }
    {
      target = "org/threeten/threeten-extra/1.5.0/threeten-extra-1.5.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/threeten/threeten-extra/1.5.0/threeten-extra-1.5.0-sources.jar";
      hash = "sha256-jnK4dBt8oq1PZT19tOrEf9XnBzULYsNZ9wjdSpQrJJ8=";
    }
    {
      target = "org/checkerframework/checker-qual/3.19.0/checker-qual-3.19.0.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/checkerframework/checker-qual/3.19.0/checker-qual-3.19.0-sources.jar";
      hash = "sha256-HyJuKQEWJHXKoBUVMElt0BBwGr1BSX689qd7VXvcNjs=";
    }
    {
      target = "org/reactivestreams/reactive-streams/1.0.3/reactive-streams-1.0.3.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/org/reactivestreams/reactive-streams/1.0.3/reactive-streams-1.0.3-sources.jar";
      hash = "sha256-1bQHCiLJscpbm1qmaEZrzKOR2+XV/oMRwwB2XBYh/ro=";
    }
    {
      target = "io/reactivex/rxjava3/rxjava/3.1.2/rxjava-3.1.2.jar";
      sourceUrl = "https://repo.maven.apache.org/maven2/io/reactivex/rxjava3/rxjava/3.1.2/rxjava-3.1.2-sources.jar";
      hash = "sha256-Rovglf/rppmeF84KIfbgf8ccMglPRIrZELUnUT1o6Nk=";
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
          -o -name '*.dll' -o -name '*.a' -o -name '*.o' \
          -o -name '*.jar' -o -name '*.wasm' -o -name '*.exe' \
          -o -name '*.bin' -o -name '*.zip' -o -name '*.tar' \
          -o -name '*.gz' -o -name '*.xz' \) -print -quit)"; then
        echo "Compiled payload in ${source.target} source archive" >&2
        exit 1
      fi
      python3 - source-${toString source.index} <<'PY'
      from pathlib import Path
      import sys

      compiled_signatures = {
          bytes.fromhex(value)
          for value in (
              "7f454c46",  # ELF
              "cafebabe",  # Java class or Mach-O universal binary
              "feedface", "cefaedfe", "feedfacf", "cffaedfe",  # Mach-O
              "0061736d",  # WebAssembly
              "213c617263683e0a",  # ar archive
              "4d5a",  # PE executable
              "504b0304", "504b0506",  # nested ZIP archives
          )
      }
      for path in Path(sys.argv[1]).rglob("*"):
          if not path.is_file():
              continue
          with path.open("rb") as input_file:
              header = input_file.read(8)
          if any(header.startswith(signature) for signature in compiled_signatures):
              raise SystemExit(f"Compiled payload in source archive: {path}")
      PY
      ${
        if source.legacyEnumPackage or false
        then ''
          # Java 5 reserved "enum" as a keyword. Compile under an equal-length
          # temporary package name, then restore the original class identity.
          python3 - source-${toString source.index} <<'PY'
          from pathlib import Path
          import sys

          for path in Path(sys.argv[1]).rglob("*.java"):
              original = path.read_bytes()
              updated = original.replace(
                  b"org.apache.commons.lang.enum",
                  b"org.apache.commons.lang.en_m",
              )
              if updated != original:
                  path.write_bytes(updated)
          PY
        ''
        else ""
      }
    '')
    sources);

  buildJars = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p classes-${toString source.index}
      ${
        if source.repairHamcrestGenerics or false
        then ''
          # Hamcrest 1.3 predates modern javac's wildcard inference. Spell
          # out the existing generic types without changing matcher behavior.
          python3 - source-${toString source.index} <<'PY'
          from pathlib import Path
          import sys

          root = Path(sys.argv[1]) / "org/hamcrest/core"
          for name, method in (("AnyOf.java", "anyOf"), ("AllOf.java", "allOf")):
              path = root / name
              original = f"return {method}(Arrays.asList(matchers));"
              replacement = (
                  f"return {name[:-5]}.<T>{method}("
                  "Arrays.<Matcher<? super T>>asList(matchers));"
              )
              source = path.read_text()
              if source.count(original) != 1:
                  raise SystemExit(f"Unexpected Hamcrest source: {path}")
              path.write_text(source.replace(original, replacement))
          PY
        ''
        else ""
      }
      ${
        if source.compileOnlyPlatformProvider or false
        then ''
          # Upstream generates this optional hook only inside Google. Keep
          # its compile-time declaration out of the JAR so the documented
          # NoClassDefFoundError fallback and external provider still work.
          provider=source-${toString source.index}/com/google/common/flogger/backend/PlatformProvider.java
          test ! -e "$provider"
          cat > "$provider" <<'JAVA'
          package com.google.common.flogger.backend;

          final class PlatformProvider {
              static Platform getPlatform() {
                  return null;
              }
          }
          JAVA
        ''
        else ""
      }
      find source-${toString source.index}${
        if source ? javaRoot
        then "/${source.javaRoot}"
        else ""
      } ${
        if source ? javaMaxDepth
        then "-maxdepth ${toString source.javaMaxDepth}"
        else ""
      } -type f -name '*.java' \
        ! -name module-info.java -print > sources-${toString source.index}.list
      test -s sources-${toString source.index}.list
      javac --release ${toString (source.javaRelease or 17)} \
        -encoding ${source.sourceEncoding or "UTF-8"} -proc:none \
        -cp ".''${classpath:+:$classpath}${extraClasspath source}" -d classes-${toString source.index} \
        @sources-${toString source.index}.list
      ${
        if source.compileOnlyPlatformProvider or false
        then ''
          provider_class=classes-${toString source.index}/com/google/common/flogger/backend/PlatformProvider.class
          test -f "$provider_class"
          rm "$provider_class"
        ''
        else ""
      }
      ${
        if source.legacyEnumPackage or false
        then ''
          python3 - classes-${toString source.index} <<'PY'
          from pathlib import Path
          import sys

          root = Path(sys.argv[1])
          for path in root.rglob("*.class"):
              original = path.read_bytes()
              updated = original.replace(
                  b"org/apache/commons/lang/en_m",
                  b"org/apache/commons/lang/enum",
              ).replace(
                  b"org.apache.commons.lang.en_m",
                  b"org.apache.commons.lang.enum",
              )
              if updated != original:
                  path.write_bytes(updated)

          temporary = root / "org/apache/commons/lang/en_m"
          temporary.rename(root / "org/apache/commons/lang/enum")
          PY
        ''
        else ""
      }
      ${
        if source.copyResources or true
        then ''
          # Runtime data and service descriptors live beside Java sources in
          # several upstream archives, including Commons Math's Sobol table.
          find source-${toString source.index} -type f ! -name '*.java' \
            ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
              relative=''${resource#source-${toString source.index}/}
              destination="classes-${toString source.index}/$relative"
              mkdir -p "$(dirname "$destination")"
              cp "$resource" "$destination"
            done
        ''
        else ""
      }
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
      bazelAsm
      buildPackages.ant
      buildPackages.unzip
      buildPackages.findutils
      buildPackages.python3
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
