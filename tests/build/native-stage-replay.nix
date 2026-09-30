##! Compares actual image stage graphs with their exact retained native sources.
{
  config,
  lib,
}: let
  replay = bundle: let
    descriptor = bundle.nativeEvaluationDescriptor;
    original = descriptor.nativeEvaluationInputs;
    evaluated = lib.evalPackageModules {
      inherit (original) packages scope;
      operatorModules = original.configuration;
      runtimeModules = original.runtimeConfiguration;
      evaluationInput = descriptor;
    };
  in
    assert evaluated.deployment.graph == bundle.nativeTransaction.graph;
    assert evaluated.deployment.scope == bundle.nativeTransaction.scope; true;
  host = config.system.build.hostDeploymentBundle;
  initrd = config.system.build.initrdDeploymentBundle;
  capsule = builtins.filter (artifact: artifact.name == "aos-host-evaluation-input") initrd.nativeResolvedPackages.artifacts;
  prepareNodes = builtins.filter (node: let
    length = builtins.length node.identity;
  in
    length >= 3
    && builtins.elemAt node.identity (length - 3) == "storageProvisioning"
    && builtins.elemAt node.identity (length - 2) == "prepare")
  (builtins.attrValues initrd.nativeTransaction.graph.nodes);
in {
  host = replay host;
  initrd = replay initrd;
  hostProfileScope = assert host.nativeTransaction.scope == ["profile" "system"]; true;
  admittedHostProjection =
    if prepareNodes == []
    then true
    else
      assert builtins.length capsule == 1;
      assert builtins.all (node: node.input.evaluation_context == "${(builtins.head capsule).path}/evaluation.json") prepareNodes; true;
}
