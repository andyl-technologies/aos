##! Preserves the embedded GPL gateway package and its release assertions.
{
  packageArguments,
  cargoFallback,
  callPackage,
  stdenv,
}: let
  compilation = callPackage ../../emulation/_crucible-qemu-bazel.nix {
    components = ["gateway"];
    sourceInventory = ../../../tools/bazel/metadata/qemu-gateway-installed-inventory.json;
  };
  execution = callPackage ../../emulation/_crucible-qemu-bazel-gateway-tests.nix {release = true;};
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    compilation.installed.gateway.overrideAttrs (previous: {
      inherit (packageArguments) runtimeDeps meta;
      # Retain the ordinary package's release assertions and separate Apache
      # process oracle without evaluating the Cargo rollback constructor.
      buildDeps = previous.buildDeps ++ [execution.tests];
      disallowedReferences = [compilation.build compilation.workspace.source];
      phases =
        previous.phases
        ++ [
          {
            name = "public-package-layout";
            script = ''
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
          bazelTestWorkspace = execution.testWorkspace;
          bazelOracle = execution.hostPackage;
          bazelOracleBuild = execution.hostBuild;
          bazelOracleWorkspace = execution.hostWorkspace;
        };
    })
