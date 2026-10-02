##! Verifies the actual lower declaration and its expanded native dependency graph.
{
  lib,
  pkgs,
}: let
  fixture = import ./_configuration-lower-fixture.nix {inherit lib pkgs;};
  input = fixture.node.input;
  nodes = builtins.attrValues fixture.evaluated.deployment.graph.nodes;
  lowerMounts = builtins.filter (node:
    builtins.elem "configurationLower" node.identity && builtins.elem "mount" node.identity)
  nodes;
  mount = assert builtins.length lowerMounts == 1; builtins.head lowerMounts;
in {
  checkedFileModes = assert input.files."runtime-config/materialized.conf".mode == "0644"; true;
  exactFileOwnership = assert builtins.attrNames input.files == builtins.attrNames input.ownership.files; true;
  exactTreeOwnership = assert builtins.attrNames input.ownership.etcTrees == ["package-tree"]; true;
  exactScriptOwnership = assert builtins.attrNames input.jobScripts == builtins.attrNames input.ownership.jobScripts; true;
  retainedTree = assert input.etcTrees
  == [
    {
      target = "package-tree";
      source = toString fixture.tree;
    }
  ];
  assert builtins.elem (toString fixture.tree) input.storePaths; true;
  explicitTreeOverride = assert input.files."package-tree/identity.txt".text == "operator-override\n"; true;
  realEnsureHandler = assert fixture.node.handler.executable == "${pkgs.aos-configuration-lower}/bin/aos-configuration-lower"; true;
  checkedMountDependency = assert builtins.elem fixture.invocation.id mount.dependencies; true;
  retainedBaselineUniverse = assert input.baselinePaths == ["runtime-config/materialized.conf"]; true;
}
