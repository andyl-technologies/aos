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
  fileEffect = name:
    fixture.evaluated.config.aos.abilities.configuration.operations.file.effects.${name};
  fileId = name: builtins.hashString "sha256" (builtins.toJSON (fileEffect name).contract.identity);
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
  declarationLifetimes = assert input.fileEffects."runtime-config/materialized.conf"
  == {
    id = fileId "materialized";
    lifetime = "instance";
  };
  assert input.fileEffects."runtime-config/retained.conf"
  == {
    id = fileId "retained";
    lifetime = "persistent";
  }; true;
  exactRetirement = assert input.retiredEffects == [(builtins.hashString "sha256" "unconfigured-retained-effect")]; true;
  persistentContent = assert input.files."runtime-config/retained.conf".text == "retained-package-policy\n";
  assert input.files."runtime-config/retained.conf".mode == "0640"; true;
  liveDeclarationIdentity = assert !(input.files ? "runtime-config/live.conf");
  assert input.fileEffects."runtime-config/live.conf"
  == {
    id = fileId "live";
    lifetime = "instance";
  }; true;
  orderedLiteralFragments = assert input.files."runtime-config/fragments.conf"
  == {
    kind = "text";
    text = "first\nsecond\n";
    mode = "0600";
  }; true;
  literalFragmentOwnership = assert input.ownership.files."runtime-config/fragments.conf" == (fileEffect "literalFragments").contract.owner;
  assert (fileEffect "literalFragments").input.owner == "root";
  assert (fileEffect "literalFragments").input.group == "root"; true;
  literalFragmentLifetimeIdentity = assert input.fileEffects."runtime-config/fragments.conf"
  == {
    id = fileId "literalFragments";
    lifetime = "persistent";
  }; true;
  deferredDeclarationRemainsLive = assert !(input.files ? "runtime-config/deferred.conf");
  assert input.fileEffects."runtime-config/deferred.conf"
  == {
    id = fileId "deferred";
    lifetime = "instance";
  }; true;
  structuredDeclarationRemainsLive = assert !(input.files ? "runtime-config/structured.json");
  assert input.fileEffects."runtime-config/structured.json"
  == {
    id = fileId "structured";
    lifetime = "instance";
  }; true;
}
