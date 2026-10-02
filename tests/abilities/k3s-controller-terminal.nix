##! Checks direct native Kubernetes handlers and typed operation preflight.
{
  lib,
  pkgs,
}: let
  object = {
    key = "sample";
    api_version = "v1";
    kind = "ConfigMap";
    namespace = "default";
    name = "sample";
    content = builtins.toJSON {
      apiVersion = "v1";
      kind = "ConfigMap";
      metadata = {
        name = "sample";
        namespace = "default";
      };
      data.value = "example";
    };
  };
  configuration = {
    aos.abilities.kubernetes.operations.ensure.effects.sample.input = {
      kubeconfig = "/etc/rancher/k3s/k3s.yaml";
      object_sets.sample.objects = [object];
    };
    aos.abilities.k3sConfiguration.operations.ensure.effects.base.input = {
      base.flannel_backend = "vxlan";
      integrations.cilium.disable_flannel = true;
    };
  };
  evaluate = packages: modules:
    lib.evalPackageModules {
      scope = ["test" "k3s-controller"];
      inherit packages;
      operatorModules = modules;
    };
  configured = evaluate [pkgs.k3s-combined] [configuration];
  nodes = builtins.attrValues configured.deployment.graph.nodes;
  handler = "${pkgs.k3s-combined}/bin/aos-kubernetes-provider";
  rejected = packages: modules: !(builtins.tryEval (builtins.deepSeq (evaluate packages modules).deployment true)).success;
in
  assert builtins.length nodes == 2;
  assert builtins.all (node: node.handler.kind == "process" && node.handler.executable == handler && node.handler.artifact == builtins.toString pkgs.k3s-combined) nodes;
  assert configured.config.aos.abilities.kubernetes.operations.ensure.effects.sample.input.object_sets.sample.objects == [object];
  assert configured.config.aos.abilities.k3sConfiguration.operations.ensure.effects.base.input.integrations.cilium.disable_flannel;
  assert configured.documentation.abilities.kubernetes.ensure.result.cluster.type.kind == "string";
  assert configured.documentation.abilities.k3sConfiguration.ensure.result.path.type.kind == "string";
  assert rejected [pkgs.kubernetes-interface] [configuration];
  assert rejected [pkgs.k3s-combined] [
    configuration
    {
      aos.abilities.kubernetes.operations.ensure.effects.invalid.input.kubeconfig = 42;
    }
  ]; true
