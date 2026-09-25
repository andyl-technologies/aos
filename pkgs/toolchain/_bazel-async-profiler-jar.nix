##! async-profiler API and Linux native library packaged for Bazel's classpath.
{
  mkDerivation,
  buildPackages,
  stdenv,
  bazelAsyncProfilerApi,
  bazelAsyncProfilerNative,
}: let
  version = "3.0";
  buildJdk = buildPackages.openjdk-17;
  platformTag =
    if stdenv.hostPlatform.isAarch64
    then "linux-arm64"
    else "linux-x64";
in
  assert stdenv.hostPlatform.isLinux;
  assert stdenv.hostPlatform.isx86_64 || stdenv.hostPlatform.isAarch64;
    mkDerivation {
      pname = "bazel-async-profiler-jar";
      inherit version;

      buildDeps = [
        buildJdk
        bazelAsyncProfilerApi
      ];
      # The library is copied into the JAR, never executed by the build machine.
      runtimeDeps = [bazelAsyncProfilerNative];

      phases = [
        {
          name = "build";
          script = ''
            export JAVA_HOME=${buildJdk}
            export PATH="$JAVA_HOME/bin:$PATH"

            mkdir -p classes/${platformTag}
            cd classes
            jar --extract --file ${bazelAsyncProfilerApi}/share/java/async-profiler-${version}.jar
            cd ..

            cp ${bazelAsyncProfilerNative}/lib/libasyncProfiler.so \
              classes/${platformTag}/libasyncProfiler.so
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
