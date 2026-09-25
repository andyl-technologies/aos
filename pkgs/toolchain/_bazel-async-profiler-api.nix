##! async-profiler Java API compiled from the upstream source tree.
{
  mkDerivation,
  fetchgit,
  buildPackages,
}: let
  version = "3.0";
  buildJdk = buildPackages.openjdk-17;
  source = fetchgit {
    url = "https://github.com/async-profiler/async-profiler.git";
    ref = "v${version}";
    rev = "4e441b4024a5873a5764a1e8b9f0bb25ad997fbf";
    hash = "sha256-Gm8KsoGnTEPjfQjfMvS1FzwQDclr6mgoGqIhfEhOO+g=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/src/api/"
      "/LICENSE"
    ];
  };
in
  mkDerivation {
    pname = "bazel-async-profiler-api";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      buildPackages.findutils
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes
          find ${source}/src/api -name '*.java' -print | sort > java-sources
          test "$(wc -l < java-sources)" -eq 4
          javac -source 7 -target 7 -proc:none -encoding UTF-8 \
            -d classes @java-sources
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          jar --create --file "$out/share/java/async-profiler-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
    ];
  }
