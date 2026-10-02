##! Ensures portable file effects retain no systemd or host-policy source.
{
  lib,
  pkgs,
}: let
  provider = pkgs.aos-configuration-provider;
  evaluated = lib.evalPackageModules {
    scope = ["profile" "portable-configuration"];
    packages = [provider];
    operatorModules = [
      {
        aos.abilities.configuration.operations.file.effects.fixture.input = {
          path = "/etc/portable-configuration-fixture";
          content = "portable";
        };
      }
    ];
  };
  graph = evaluated.deployment.graph;
  nodes = builtins.attrValues graph.nodes;
in {
  configurationOnly = builtins.length nodes == 1 && (builtins.head nodes).identity == ["profile" "portable-configuration" "@environment" "configuration" "file" "fixture"];
  pinnedProvider = (builtins.head nodes).handler.executable == "${provider}/bin/aos-configuration-provider";
  neutralModuleDependency = map (package: package.pname) provider.moduleDeps == ["service-management"];
  portableRuntimeDependencies = map (package: package.pname) provider.runtimeDeps == ["python3" "bash"];
  checkedGraph = builtins.deepSeq evaluated.deployment true;
}
