##! Checks the authored marker graph retains real deferred prerequisite edges.
let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = import ./_fixture-payload.nix "dependency-barrier";
  artifact = {
    name = "native-dependency-barrier";
    version = "1";
    path = toString payload;
    outputs.out = toString payload;
    mainProgram = "native-dependency-barrier";
  };
  source = builtins.path {
    path = ../abilities/native-dependency-barrier/module;
    name = "native-dependency-barrier-module";
  };
  evaluated = lib.evalPackageModules {
    scope = ["test" "dependency-barrier"];
    packageModules = [
      {
        name = artifact.name;
        version = "1";
        configRoot = toString source;
        module = "${source}/module.nix";
        artifacts = {
          package = artifact;
          dependencies = {};
        };
      }
    ];
    operatorModules = [
      ({config, ...}: {
        aos.nativeDependencyBarrier.requests = {
          parent.name = "parent";
          child = {
            name = "child";
            parent = config.aos.abilities.nativeDependencyBarrier.operations.ensure.effects.parent.outputs.resource;
          };
        };
      })
    ];
  };
  nodes = builtins.attrValues evaluated.deployment.graph.nodes;
  find = name: builtins.head (builtins.filter (node: builtins.elem name node.identity) nodes);
  parent = find "parent";
  child = find "child";
  parentId = builtins.head (builtins.filter (id: evaluated.deployment.graph.nodes.${id} == parent) (builtins.attrNames evaluated.deployment.graph.nodes));
in {
  actualNativeMarkerNodes = builtins.length nodes == 2;
  deferredResultOrdersChild = child.dependencies == [parentId];
  originalMarkerHandlerRetained = parent.handler.kind == "process" && parent.handler.artifact == artifact.path;
}
