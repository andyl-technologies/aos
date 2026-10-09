##! Compares actual image stage graphs with their exact retained native sources.
{
  config,
  lib,
}: let
  evaluate = bundle: let
    descriptor = bundle.nativeEvaluationDescriptor;
    original = descriptor.nativeEvaluationInputs;
  in
    lib.evalPackageModules {
      inherit (original) packages scope;
      operatorModules = original.configuration;
      runtimeModules = original.runtimeConfiguration;
      evaluationInput = descriptor;
    };
  replay = bundle: let
    evaluated = evaluate bundle;
  in
    assert evaluated.deployment.graph == bundle.nativeTransaction.graph;
    assert evaluated.deployment.scope == bundle.nativeTransaction.scope; true;
  host = config.system.build.hostDeploymentBundle;
  initrd = config.system.build.initrdDeploymentBundle;
  replayedHost = (evaluate host).config;
  localePackages = builtins.filter (package: (package.pname or null) == "glibc-locales") host.nativeEvaluationDescriptor.nativeEvaluationInputs.packages;
  localeOnly = lib.evalPackageModules {
    packages = localePackages;
    scope = ["profile" "locale-only"];
  };
  capsule = builtins.filter (artifact: artifact.name == "aos-host-evaluation-input") initrd.nativeResolvedPackages.artifacts;
  prepareNodes = builtins.filter (node: let
    length = builtins.length node.identity;
  in
    length
    >= 3
    && builtins.elemAt node.identity (length - 3) == "storageProvisioning"
    && builtins.elemAt node.identity (length - 2) == "prepare")
  (builtins.attrValues initrd.nativeTransaction.graph.nodes);
in {
  host = replay host;
  initrd = replay initrd;
  hostLocaleDefaults = assert replayedHost.environment.sessionVariables.LANG == config.environment.sessionVariables.LANG;
  assert replayedHost.environment.sessionVariables.LOCPATH == config.environment.sessionVariables.LOCPATH;
  assert map toString replayedHost.aos.system.localePackages == map toString config.aos.system.localePackages; true;
  localePackageIsInert = assert builtins.length localePackages == 1;
  assert localeOnly.deployment.graph.nodes == {}; true;
  initrdExcludesLocalePayload = assert builtins.all (artifact: artifact.name != "glibc-locales") initrd.nativeResolvedPackages.artifacts;
  assert builtins.all (package: !(lib.hasInfix (toString package) (builtins.toJSON initrd.nativeTransaction.graph))) localePackages; true;
  hostProfileScope = assert host.nativeTransaction.scope == ["profile" "system"]; true;
  admittedHostProjection =
    if prepareNodes == []
    then true
    else
      assert builtins.length capsule == 1;
      assert builtins.all (node: node.input.evaluation_context == "${(builtins.head capsule).path}/evaluation.json") prepareNodes; true;
}
