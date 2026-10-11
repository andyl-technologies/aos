##! Authors disposable Kubernetes and K3s configuration targets for live flights.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.nativeKubernetesQualification;
  effects = config.aos.abilities;
  token = effects.configuration.operations.file.effects.native-kubernetes-token;
  markers = effects.nativeDependencyBarrier.operations.ensure.effects;
  lifecycle = effects.serviceManagement.operations.realize.effects.k3s;
  document = {
    apiVersion = "v1";
    kind = "ConfigMap";
    metadata = {
      name = "native-qualification-owned";
      namespace = "default";
    };
    data.message = cfg.message;
  };
in {
  options.aos.nativeKubernetesQualification = {
    objects = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the disposable object target.";
    };
    configuration = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the disposable configuration target.";
    };
    message = lib.mkOption {
      type = lib.types.str;
      default = "baseline";
      description = "Authored ConfigMap payload.";
    };
    label = lib.mkOption {
      type = lib.types.str;
      default = "baseline";
      description = "Authored configuration label.";
    };
  };
  config = {
    aos.nativeHandlerInterception.native-handler-interception-k3s-combined.operations = [
      {
        ability = "kubernetes";
        name = "ensure";
      }
      {
        ability = "k3sConfiguration";
        name = "ensure";
      }
    ];
    k3s = {
      enable = true;
      token.name = "native-qualification-token";
    };
    aos.nativeDependencyBarrier.requests = lib.mkMerge [
      (lib.mkIf cfg.objects {
        kubernetes-parent.name = "kubernetes-parent";
        kubernetes-child = {
          name = "kubernetes-child";
          parent = effects.kubernetes.operations.ensure.effects.native-qualification.outputs.cluster;
        };
      })
      (lib.mkIf cfg.configuration {
        configuration-parent.name = "configuration-parent";
        configuration-child = {
          name = "configuration-child";
          parent = effects.k3sConfiguration.operations.ensure.effects.native-qualification.outputs.path;
        };
      })
    ];
    aos.abilities = {
      configuration.operations.file.effects.native-kubernetes-token.input = {
        path = "/run/credentials/@system/native-qualification-token";
        content = "native-qualification-public-fixture-token\n";
        mode = "0600";
      };
      credential.operations.deliver.effects.k3s.after = [token.outputs.path];
      k3sConfiguration.operations.ensure.effects.native-qualification = lib.mkIf cfg.configuration {
        after = [markers.configuration-parent.outputs.resource];
        lifetime = "persistent";
        timeoutMs = 10000;
        input = {
          path = "/run/aos/k3s/qualification.json";
          base.node_labels."qualification.andyl.com/generation" = cfg.label;
        };
      };
      kubernetes.operations.ensure.effects.native-qualification = lib.mkIf cfg.objects {
        lifetime = "persistent";
        timeoutMs = 10000;
        after = [lifecycle.outputs.resource markers.kubernetes-parent.outputs.resource];
        input = {
          kubeconfig = "/etc/rancher/k3s/k3s.yaml";
          object_sets.qualification.objects = [
            {
              key = "owned";
              api_version = "v1";
              kind = "ConfigMap";
              namespace = "default";
              name = "native-qualification-owned";
              content = builtins.toJSON document;
            }
          ];
        };
      };
    };
  };
}
