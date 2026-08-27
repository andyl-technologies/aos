##! Focused evaluation and rendering checks for the k3s configuration modules.
{
  pkgs,
  lib,
}: let
  evaluateRole = {
    package,
    name,
    host,
  }:
    lib.evalModules {
      modules = [
        {
          options.${name} = {
            config = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
            };
            credentials = lib.mkOption {
              type = lib.types.attrsOf lib.types.attrs;
              default = {};
            };
          };
        }
      ];
      operatorModules = [host];
      packageModules = [
        {
          inherit name;
          authorization = {
            owns = ["k3s"];
            contributes = {};
          };
          configRoot = ../../pkgs/kubernetes/_k3s-config;
          module = ../../pkgs/kubernetes/_k3s-config/module.nix;
          outputs = {
            self = builtins.toString package;
            dependencies = {};
          };
        }
      ];
    };

  token = {ref = "system-credential:k3s-token";};
  worker = evaluateRole {
    package = pkgs.k3s-worker;
    name = "k3s-worker";
    host = {
      k3s = {
        enable = true;
        serverUrl = "https://server.example:6443";
        inherit token;
        node = {
          name = "worker-1";
          labels."node-role.kubernetes.io/worker" = "true";
        };
        integrations = {
          cni.cilium = {
            disableFlannel = true;
            disableNetworkPolicy = true;
            disableKubeProxy = true;
          };
          csi.local.nodeLabels."storage.aos.io/local" = "true";
        };
      };
    };
  };
  controlPlane = evaluateRole {
    package = pkgs.k3s-control-plane;
    name = "k3s-control-plane";
    host.k3s = {
      enable = true;
      inherit token;
      server = {
        clusterInit = true;
        disableComponents = ["traefik" "servicelb"];
        tlsSans = ["api.example.test"];
      };
      kubeconfigMode = "0640";
    };
  };
  combined = evaluateRole {
    package = pkgs.k3s-combined;
    name = "k3s-combined";
    host.k3s = {
      enable = true;
      inherit token;
      serverUrl = "https://server.example:6443";
      networking.flannelBackend = "wireguard-native";
    };
  };
  disabled = evaluateRole {
    package = pkgs.k3s-worker;
    name = "k3s-worker";
    host = {};
  };

  allAssertionsHold = evaluated:
    builtins.all (assertion: assertion.assertion) evaluated.assertions;
  workerEnv = worker.config."k3s-worker".config.env;
  controlPlaneEnv = controlPlane.config."k3s-control-plane".config.env;
  combinedEnv = combined.config."k3s-combined".config.env;

  checks = [
    {
      assertion = worker.config.k3s.role == "worker";
      message = "k3s worker role must be fixed by its provider";
    }
    {
      assertion = workerEnv.K3S_ENABLED == "true";
      message = "enabled worker must render K3S_ENABLED";
    }
    {
      assertion = workerEnv.K3S_URL == "https://server.example:6443";
      message = "worker server URL must project to the env artifact";
    }
    {
      assertion = workerEnv.K3S_FLANNEL_BACKEND == "none";
      message = "external CNI must disable Flannel";
    }
    {
      assertion = workerEnv.K3S_DISABLE_NETWORK_POLICY == "true";
      message = "external CNI may disable built-in network policy";
    }
    {
      assertion = workerEnv.K3S_DISABLE_KUBE_PROXY == "true";
      message = "external CNI may disable kube-proxy";
    }
    {
      assertion = lib.hasInfix "storage.aos.io/local=true" workerEnv.K3S_NODE_LABEL;
      message = "CSI integration labels must compose with operator labels";
    }
    {
      assertion = worker.config."k3s-worker".credentials.token.ref == token.ref;
      message = "token must remain an opaque credential reference";
    }
    {
      assertion = controlPlane.config.k3s.role == "control-plane";
      message = "control-plane role must be fixed by its provider";
    }
    {
      assertion = controlPlaneEnv.K3S_CLUSTER_INIT == "true";
      message = "control-plane cluster initialization must render";
    }
    {
      assertion = controlPlaneEnv.K3S_DISABLE == "traefik,servicelb";
      message = "disabled server components must render deterministically";
    }
    {
      assertion = controlPlaneEnv.K3S_KUBECONFIG_MODE == "0640";
      message = "kubeconfig mode must render";
    }
    {
      assertion = combined.config.k3s.role == "combined";
      message = "combined role must be fixed by its provider";
    }
    {
      assertion = combinedEnv.K3S_FLANNEL_BACKEND == "wireguard-native";
      message = "combined networking configuration must render";
    }
    {
      assertion = disabled.config."k3s-worker".config.env.K3S_ENABLED == "false";
      message = "disabled k3s must render a clean service condition";
    }
    {
      assertion = allAssertionsHold worker && allAssertionsHold controlPlane && allAssertionsHold combined;
      message = "valid role configurations must satisfy k3s assertions";
    }
  ];
  contract = builtins.foldl' (value: check: lib.throwIfNot check.assertion check.message value) true checks;
in
  pkgs.mkDerivation {
    pname = "k3s-config-check";
    version = "0";
    src = null;

    inherit contract;
    workerExpose = pkgs.k3s-worker.expose;
    controlPlaneExpose = pkgs.k3s-control-plane.expose;
    combinedExpose = pkgs.k3s-combined.expose;

    phases = [
      {
        name = "check";
        script = ''
          : "$contract"

          for expose in "$workerExpose" "$controlPlaneExpose" "$combinedExpose"; do
            test -f "$expose/manifest.json"
            grep -q '"path":"/etc/aos/packages/k3s-' "$expose/manifest.json"
            grep -q '"name":"token"' "$expose/manifest.json"
            grep -q '"encrypted":true' "$expose/manifest.json"
            grep -q 'EnvironmentFile=/etc/aos/packages/k3s-' "$expose/units/k3s.service"
            grep -q 'ExecStart=.*/bin/k3s-k3s-' "$expose/units/k3s.service"
            grep -q 'ExecCondition=.*/bin/k3s-k3s-' "$expose/units/k3s-preflight.service"
          done

          mkdir -p "$out"
          printf '%s\n' ok > "$out/result"
        '';
      }
    ];

    meta.description = "Typed k3s role configuration contract checks";
  }
