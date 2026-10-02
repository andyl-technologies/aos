##! Native Kubernetes role declarations preserve service policy and add-on composition.
{
  lib,
  pkgs,
}: let
  evaluate = packages: configuration:
    lib.evalPackageModules {
      scope = ["test" "kubernetes-services"];
      packages = packages ++ [pkgs.systemd pkgs.aos-network-ruleset-provider];
      operatorModules = [configuration];
    };
  workerConfiguration = {
    k3s = {
      enable = true;
      serverUrl = "https://control.example.test:6443";
      token.name = "k3s-token";
    };
  };
  worker = evaluate [pkgs.k3s-worker] workerConfiguration;
  controlPlane = evaluate [pkgs.k3s-control-plane] {
    k3s = {
      enable = true;
      token.name = "control-plane-token";
      node.name = "operator-control-plane";
    };
  };
  roles = import ../../pkgs/kubernetes/_k3s-config/roles.nix;
  launcherFactory = import ../../pkgs/kubernetes/_k3s-common.nix {
    inherit lib;
    pkgs = {
      inherit (pkgs) k3s;
      writeShellScriptBin = name: script: {inherit name script;};
    };
  };
  controlPlaneLauncher = launcherFactory.launcher "k3s-control-plane" roles.k3s-control-plane.command;
  combined = evaluate [pkgs.k3s-combined pkgs.cilium pkgs.longhorn-manager] {
    k3s = {
      enable = true;
      token.name = "k3s-token";
    };
    aos.cilium = {
      enable = true;
      operatorReplicas = 2;
    };
    aos.longhorn = {
      enable = true;
      defaultReplicaCount = 4;
      nodeLabel = "storage";
    };
  };
  disabled = evaluate [pkgs.k3s-worker] {};
  forceDisabled = evaluate [pkgs.k3s-worker] ({lib, ...}:
    workerConfiguration
    // {
      aos.services.k3s.enable = lib.mkForce false;
    });
  roleNodes = evaluated:
    builtins.filter (node:
      lib.last node.identity
      == "k3s"
      || builtins.elem (builtins.elemAt node.identity (builtins.length node.identity - 3)) ["kubernetes" "k3sConfiguration"])
    (builtins.attrValues evaluated.deployment.graph.nodes);
  service = worker.config.aos.services.k3s;
  workerEffects = worker.config.aos.abilities;
  combinedEffects = combined.config.aos.abilities;
  objects = combinedEffects.kubernetes.operations.ensure.effects.cluster.input.object_sets;
  cilium = builtins.fromJSON (builtins.head objects.cilium.objects).content;
  longhorn = builtins.fromJSON (builtins.head objects.longhorn.objects).content;
  rejects = packages: configuration: let
    evaluated = evaluate packages configuration;
  in
    !(builtins.tryEval (builtins.deepSeq [
        (evaluated.config.k3s or {})
        (evaluated.config.aos.cilium or {})
        (evaluated.config.aos.longhorn or {})
        evaluated.deployment
      ]
      true)).success;
in
  assert worker.deployment.graph.order != [];
  assert controlPlane.deployment.graph.order != [];
  assert controlPlane.config.k3s.role == "control-plane";
  assert roles.k3s-control-plane.command == "server --disable-agent --egress-selector-mode=cluster";
  assert roles.k3s-worker.command == "agent";
  assert roles.k3s-combined.command == "server";
  assert lib.hasInfix ''exec ${pkgs.k3s}/bin/k3s server --disable-agent --egress-selector-mode=cluster --config "$configuration" "$@"'' controlPlaneLauncher.script;
  assert (builtins.head controlPlane.config.aos.services.k3s.lifecycle.start).executable.arguments
  == [
    controlPlane.config.aos.abilities.k3sConfiguration.operations.ensure.effects.base.outputs.path
    controlPlane.config.aos.abilities.credential.operations.deliver.effects.k3s.outputs.path
  ];
  assert controlPlane.config.aos.services.k3s.environment.variables.K3S_NODE_NAME == "operator-control-plane";
  assert combined.deployment.graph.order != [];
  assert roleNodes disabled == [];
  assert roleNodes forceDisabled == [];
  assert service.lifecycle.execution_model == "foreground";
  assert service.lifecycle.restart == "always";
  assert service.lifecycle.start_timeout_millis == 90000 && service.lifecycle.start_timeout_unbounded;
  assert service.lifecycle.stop_timeout_millis == 90000;
  assert service.supervision.startup_protocol == "notification";
  assert service.supervision.notification_access == "main-process";
  assert service.policy.hardening.allow_privilege_escalation;
  assert service.policy.hardening.resource_control_delegation;
  assert service.policy.hardening.operation_profile == "privileged";
  assert service.isolation.privilege == "privileged";
  assert service.isolation.termination_scope == "main-process";
  assert service.resources.open_files.value == 1048576;
  assert (builtins.head service.lifecycle.start).executable.path == "${pkgs.k3s-worker}/bin/k3s-role-start";
  assert workerEffects.credential.operations.deliver.effects.k3s.input.name == "k3s-token";
  assert workerEffects.kernelModules.operations.ensure.effects.k3s.input.required;
  assert builtins.elem "br_netfilter" workerEffects.kernelModules.operations.ensure.effects.k3s.input.modules;
  assert builtins.elem "xt_physdev" workerEffects.kernelModules.operations.ensure.effects.k3s.input.modules;
  assert builtins.elem "xt_physdev" combinedEffects.kernelModules.operations.ensure.effects.k3s.input.modules;
  assert workerEffects.kernelTunables.operations.ensure.effects.settings.input.values."net.ipv4.ip_forward" == "1";
  assert workerEffects.network.operations.ready.effects.k3s.input.scope == "address-configured";
  assert workerEffects.kubernetes.operations.ensure.effects == {};
  assert combinedEffects.k3sConfiguration.operations.ensure.effects.base.input.integrations.cilium.disable_flannel;
  assert combinedEffects.k3sConfiguration.operations.ensure.effects.base.input.integrations.longhorn.node_labels."node.longhorn.io/create-default-disk" == "storage";
  assert builtins.attrNames objects == ["cilium" "longhorn"];
  assert cilium.spec.chart == "cilium";
  assert (builtins.fromJSON cilium.spec.valuesContent).operator.replicas == 2;
  assert longhorn.spec.targetNamespace == "longhorn-system";
  assert (builtins.fromJSON longhorn.spec.valuesContent).persistence.defaultClassReplicaCount == 4;
  assert rejects [pkgs.k3s-worker] {k3s.enable = true;};
  assert rejects [pkgs.k3s-combined pkgs.cilium] {aos.cilium.operatorReplicas = 0;};
  assert rejects [pkgs.k3s-combined pkgs.longhorn-manager] {aos.longhorn.nodeLabel = "invalid value";}; true
