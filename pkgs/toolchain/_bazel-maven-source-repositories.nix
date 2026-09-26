##! Local Bazel repository overrides for Maven JARs compiled from source.
{
  mkDerivation,
  mavenPackage,
}: let
  repositoryName = target:
    "rules_jvm_external++maven+"
    + builtins.replaceStrings ["/" "." "-"] ["_" "_" "_"] (builtins.dirOf target);

  repository = target:
    mkDerivation {
      pname = "bazel-maven-source-repository";
      version = "1";
      src = mavenPackage;

      buildDeps = [];
      runtimeDeps = [mavenPackage];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/file"
            printf 'workspace(name = "bazel_maven_source")\n' > "$out/WORKSPACE"
            cp ${mavenPackage}/maven/${target} "$out/file/artifact.jar"
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
    mavenPackage.passthru.sourceTargets)
