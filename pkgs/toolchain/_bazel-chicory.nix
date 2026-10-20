##! Chicory WebAssembly runtime compiled from pinned Java sources for Bazel.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  bazelMavenBootstrap ? null,
  chicoryVersion ? "1.1.0",
  chicoryRev ? "469f7b273cc05db1db7ac2a5d59e91b41fcda8cc",
  chicoryHash ? "sha256-US+EF2nP1DnZPO4wGMVPmJBq8IrlenaDKDkVUWdwGbw=",
}: let
  version = chicoryVersion;
  source = fetchgit {
    url = "https://github.com/dylibso/chicory.git";
    ref = version;
    rev = chicoryRev;
    hash = chicoryHash;
    name = "chicory-${version}-source-only";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    sparsePaths =
      [
        "wasm/src/main/java"
        "runtime/src/main/java"
        "LICENSE"
      ]
      ++ (
        if builtins.compareVersions version "1.5.0" >= 0
        then ["log/src/main/java"]
        else ["wasm/pom.xml" "runtime/pom.xml"]
      );
  };
  jdk = buildPackages.openjdk-21;
in
  mkDerivation {
    pname = "bazel-chicory";
    inherit version;
    src = source;

    buildDeps =
      [jdk buildPackages.findutils]
      ++ (
        if bazelMavenBootstrap == null
        then []
        else [bazelMavenBootstrap]
      );
    runtimeDeps = [jdk];

    phases = [
      {
        name = "build";
        script = ''
          mkdir classes
          set -- "$src/wasm/src/main/java" "$src/runtime/src/main/java"
          if test -d "$src/log/src/main/java"; then
            set -- "$@" "$src/log/src/main/java"
          fi
          find "$@" -name '*.java' -type f -print > sources.txt
          ${jdk}/bin/javac -encoding UTF-8 \
            ${
            if bazelMavenBootstrap == null
            then ""
            else ''-cp ${bazelMavenBootstrap}/maven/com/google/errorprone/error_prone_annotations/2.36.0/error_prone_annotations-2.36.0.jar''
          } \
            -d classes @sources.txt
          ${jdk}/bin/jar --create --file chicory.jar -C classes .
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 chicory.jar "$out/share/java/chicory-${version}.jar"
          install -Dm644 "$src/LICENSE" \
            "$out/share/licenses/bazel-chicory/LICENSE"
        '';
      }
    ];
  }
