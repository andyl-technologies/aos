##! Preserves the public plugin package and its release assertions with Bazel.
{
  packageArguments,
  cargoFallback,
  callPackage,
  stdenv,
}: let
  compilation = callPackage ./_crucible-qemu-bazel.nix {
    components = ["plugin"];
    sourceInventory = ../../tools/bazel/metadata/qemu-plugin-installed-inventory.json;
  };
  execution = callPackage ./_crucible-qemu-bazel-plugin-tests.nix {release = true;};
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    compilation.installed.plugin.overrideAttrs (previous: {
      inherit (packageArguments) platformSupport qualification runtimeDeps meta;
      # The ordinary package runs release unit/integration tests before install.
      # Keep those assertions mandatory without evaluating the Cargo oracle.
      buildDeps = previous.buildDeps ++ [execution.tests];
      disallowedReferences = [compilation.build compilation.workspace.source];
      phases =
        previous.phases
        ++ [
          {
            name = "public-package-layout";
            script = ''
              # Retain export diagnostics with the compilation evidence.
              rm "$out/nix-support/bazel-package.json"
            '';
          }
        ];
      passthru =
        packageArguments.passthru
        // {
          buildDriver = "bazel";
          inherit cargoFallback;
          bazelBuild = compilation.build;
          bazelWorkspace = compilation.workspace;
          bazelTests = execution.tests;
          bazelTestWorkspace = execution.workspace;
          bazelOracle = execution.hostPackage;
          bazelOracleBuild = execution.hostBuild;
          bazelOracleWorkspace = execution.hostWorkspace;
        };
    })
