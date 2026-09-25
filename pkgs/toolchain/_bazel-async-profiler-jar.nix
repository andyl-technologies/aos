##! async-profiler API and Linux native library packaged for Bazel's classpath.
{
  mkDerivation,
  buildPackages,
  bazelAsyncProfilerApi,
  bazelAsyncProfilerNative,
}: let
  version = "3.0";
  buildJdk = buildPackages.openjdk-17;
in
  mkDerivation {
    pname = "bazel-async-profiler-jar";
    inherit version;

    buildDeps = [
      buildJdk
      bazelAsyncProfilerApi
      bazelAsyncProfilerNative
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes/linux-x64
          cd classes
          jar --extract --file ${bazelAsyncProfilerApi}/share/java/async-profiler-${version}.jar
          cd ..

          cp ${bazelAsyncProfilerNative}/lib/libasyncProfiler.so \
            classes/linux-x64/libasyncProfiler.so
          jar --create --file async-profiler-${version}.jar \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          cp async-profiler-${version}.jar "$out/share/java/"
        '';
      }
    ];
  }
