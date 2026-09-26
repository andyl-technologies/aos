##! Local Bazel repository overrides for Maven JARs compiled from source.
{
  mkDerivation,
  mavenBootstrap,
}: let
  repositoryName = target:
    "rules_jvm_external++maven+"
    + builtins.replaceStrings ["/" "." "-"] ["_" "_" "_"] (builtins.dirOf target);

  repository = target:
    mkDerivation {
      pname = "bazel-maven-source-repository";
      version = "1";
      src = mavenBootstrap;

      buildDeps = [];
      runtimeDeps = [mavenBootstrap];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/file"
            printf 'workspace(name = "bazel_maven_source")\n' > "$out/WORKSPACE"
            cp ${mavenBootstrap}/maven/${target} "$out/file/artifact.jar"
            cat > "$out/file/BUILD.bazel" <<'BUILD'
            package(default_visibility = ["//visibility:public"])
            filegroup(name = "file", srcs = ["artifact.jar"])
            BUILD
          '';
        }
      ];
    };
in
  builtins.listToAttrs (builtins.map (target: {
      name = repositoryName target;
      value = repository target;
    })
    mavenBootstrap.passthru.sourceTargets)
