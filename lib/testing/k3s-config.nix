##! Focused evaluation and rendering checks for the k3s configuration modules.
{
  pkgs,
  lib,
}: let
  evaluateRole = {
    package,
    name,
    host,
    additionalPackageModules ? [],
  }:
    lib.evalModules {
      modules = [
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
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
      packageModules =
        [
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
        ]
        ++ additionalPackageModules;
    };

  token = {ref = "system-credential:k3s-token";};
  resourceGrants = [
    {
      contribution = "cilium";
      apiVersion = "helm.cattle.io/v1";
      kind = "HelmChart";
      name = "cilium";
      namespace = "kube-system";
    }
    {
      contribution = "longhorn";
      apiVersion = "helm.cattle.io/v1";
      kind = "HelmChart";
      name = "longhorn";
      namespace = "kube-system";
    }
    {
      contribution = "canonical-fixture";
      apiVersion = "testing.aos/v1";
      kind = "CanonicalFixture";
      name = "canonical-fixture";
      namespace = null;
    }
  ];
  integrationModules = [
    {
      name = "cilium";
      authorization = {
        owns = ["cilium"];
        contributes.k3s = [
          "integrations.cni.cilium"
          "integrations.resources.cilium"
        ];
      };
      configRoot = ../../pkgs/kubernetes/_cilium-config;
      module = ../../pkgs/kubernetes/_cilium-config/module.nix;
      outputs = {
        self = builtins.toString pkgs.cilium;
        dependencies = {};
      };
    }
    {
      name = "longhorn-manager";
      authorization = {
        owns = ["longhorn"];
        contributes.k3s = [
          "integrations.csi.longhorn"
          "integrations.resources.longhorn"
        ];
      };
      configRoot = ../../pkgs/storage/_longhorn-config;
      module = ../../pkgs/storage/_longhorn-config/module.nix;
      outputs = {
        self = builtins.toString pkgs.longhorn-manager;
        dependencies = {
          longhorn-engine = builtins.toString pkgs.longhorn-engine;
          longhorn-instance-manager = builtins.toString pkgs.longhorn-instance-manager;
        };
      };
    }
  ];
  canonicalFixture = {
    apiVersion = "testing.aos/v1";
    kind = "CanonicalFixture";
    name = "canonical-fixture";
    namespace = null;
    priority = 300;
    spec = {
      enabled = true;
      generation = 7;
      aboveBinary64ExactInteger = 9007199254740993;
      maximumI64 = 9223372036854775807;
      minimumI64 = -9223372036854775807 - 1;
      nullable = null;
      nested = [
        {
          label = "café/雪";
          values = [0 1 2];
        }
      ];
    };
  };
  duplicateGrant = {
    contribution = "cilium-shadow";
    apiVersion = "helm.cattle.io/v1";
    kind = "HelmChart";
    name = "cilium";
    namespace = "kube-system";
  };
  duplicateCiliumResource = {
    apiVersion = "helm.cattle.io/v1";
    kind = "HelmChart";
    name = "cilium";
    namespace = "kube-system";
    priority = 101;
    spec = {
      chart = "cilium";
      repo = "https://helm.cilium.io/";
      targetNamespace = "kube-system";
      version = "1.17.3";
      valuesContent = builtins.toJSON {
        kubeProxyReplacement = true;
        operator.replicas = 1;
      };
    };
  };
  workerWith = {
    grants,
    additionalResources ? {},
  }:
    evaluateRole {
      package = pkgs.k3s-worker;
      name = "k3s-worker";
      additionalPackageModules = integrationModules;
      host = {
        cilium.enable = true;
        longhorn = {
          enable = true;
          defaultReplicaCount = 2;
        };
        k3s = {
          enable = true;
          serverUrl = "https://server.example:6443";
          inherit token;
          integrations = {
            resourceGrants = grants;
            resources = {canonical-fixture = canonicalFixture;} // additionalResources;
          };
          node = {
            name = "worker-1";
            labels."node-role.kubernetes.io/worker" = "true";
          };
        };
      };
    };
  workerWithGrants = grants: workerWith {inherit grants;};
  worker = workerWithGrants resourceGrants;
  reorderedGrantWorker = workerWithGrants (builtins.reverseList resourceGrants);
  mismatchedGrantWorker = workerWithGrants ([
      ((builtins.head resourceGrants) // {namespace = "default";})
    ]
    ++ builtins.tail resourceGrants);
  unauthorizedWorker = workerWithGrants [];
  duplicateIdentityWorker = workerWith {
    grants = resourceGrants ++ [duplicateGrant];
    additionalResources.cilium-shadow = duplicateCiliumResource;
  };
  invalidNumericWorker = builtins.tryEval (builtins.toJSON ((workerWith {
      grants = resourceGrants;
      additionalResources.canonical-fixture =
        canonicalFixture
        // {
          spec = canonicalFixture.spec // {generation = 1.5;};
        };
    })
    .config
    ."k3s-worker"
    .config
    .addons));
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
  workerAddons = worker.config."k3s-worker".config.addons;
  workerPayload = builtins.removeAttrs workerAddons ["revision"];
  expectedWorkerRevision = "sha256:${builtins.hashString "sha256" (builtins.toJSON workerPayload)}";
  ciliumObject = (builtins.head workerAddons.resources).object;
  ciliumValues = builtins.fromJSON ciliumObject.spec.valuesContent;
  longhornObject = (builtins.elemAt workerAddons.resources 1).object;
  longhornValues = builtins.fromJSON longhornObject.spec.valuesContent;
  canonicalResource = builtins.elemAt workerAddons.resources 2;
  canonicalObject = canonicalResource.object;
  controlPlaneEnv = controlPlane.config."k3s-control-plane".config.env;
  combinedEnv = combined.config."k3s-combined".config.env;

  workerAddonsFile = pkgs.writeTextFile {
    name = "k3s-worker-addons.json";
    destination = "/addons.json";
    text = builtins.toJSON workerAddons;
  };
  tamperedWorkerAddonsFile = pkgs.writeTextFile {
    name = "k3s-worker-addons-tampered.json";
    destination = "/addons.json";
    text = builtins.toJSON (workerAddons
      // {
        revision = "sha256:${builtins.concatStringsSep "" (builtins.genList (_: "0") 64)}";
      });
  };
  tamperedObjectResources =
    [
      ((builtins.head workerAddons.resources)
        // {
          revision = "sha256:${builtins.concatStringsSep "" (builtins.genList (_: "0") 64)}";
        })
    ]
    ++ builtins.tail workerAddons.resources;
  tamperedObjectPayload = workerPayload // {resources = tamperedObjectResources;};
  tamperedObjectAddonsFile = pkgs.writeTextFile {
    name = "k3s-worker-object-revision-tampered.json";
    destination = "/addons.json";
    text = builtins.toJSON (tamperedObjectPayload
      // {
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON tamperedObjectPayload)}";
      });
  };
  floatingObject =
    canonicalObject
    // {
      spec = canonicalObject.spec // {generation = 1.5;};
    };
  floatingResources = [
    (builtins.head workerAddons.resources)
    (builtins.elemAt workerAddons.resources 1)
    (canonicalResource
      // {
        object = floatingObject;
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON floatingObject)}";
      })
  ];
  floatingPayload = workerPayload // {resources = floatingResources;};
  floatingAddonsFile = pkgs.writeTextFile {
    name = "k3s-worker-addons-floating-number.json";
    destination = "/addons.json";
    text = builtins.toJSON (floatingPayload
      // {
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON floatingPayload)}";
      });
  };
  extendedWorkerAddonsFile = pkgs.writeTextFile {
    name = "k3s-worker-addons-extended.json";
    destination = "/addons.json";
    text = builtins.toJSON (workerAddons // {unexpected = true;});
  };

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
      assertion = lib.hasInfix "node.longhorn.io/create-default-disk=true" workerEnv.K3S_NODE_LABEL;
      message = "CSI integration labels must compose with operator labels";
    }
    {
      assertion =
        workerAddons.schema
        == "aos.kubernetes-resources/v2"
        && workerAddons.role == "worker"
        && workerAddons.revision == expectedWorkerRevision
        && reorderedGrantWorker.config."k3s-worker".config.addons.revision == workerAddons.revision
        && builtins.length workerAddons.resources == 3
        && (builtins.head workerAddons.resources).name == "cilium"
        && (builtins.elemAt workerAddons.resources 1).name == "longhorn"
        && ciliumObject.apiVersion == "helm.cattle.io/v1"
        && ciliumObject.kind == "HelmChart"
        && ciliumObject.metadata
        == {
          name = "cilium";
          namespace = "kube-system";
        }
        && ciliumObject.spec.version == "1.17.3"
        && ciliumValues
        == {
          kubeProxyReplacement = true;
          operator.replicas = 1;
        }
        && longhornObject.metadata.name == "longhorn"
        && longhornObject.spec.version == "1.8.1"
        && longhornValues.defaultSettings.defaultReplicaCount == "2"
        && longhornValues.persistence.defaultClassReplicaCount == 2
        && canonicalResource.revision
        == "sha256:${builtins.hashString "sha256" (builtins.toJSON canonicalObject)}"
        && canonicalObject.metadata == {name = "canonical-fixture";}
        && canonicalObject.spec.generation == 7
        && canonicalObject.spec.aboveBinary64ExactInteger == 9007199254740993
        && canonicalObject.spec.maximumI64 == 9223372036854775807
        && canonicalObject.spec.minimumI64 == -9223372036854775807 - 1
        && canonicalObject.spec.nested
        == [
          {
            label = "café/雪";
            values = [0 1 2];
          }
        ];
      message = "Kubernetes resource contributions must render in a versioned deterministic bundle";
    }
    {
      assertion =
        !allAssertionsHold unauthorizedWorker
        && !allAssertionsHold mismatchedGrantWorker;
      message = "a Kubernetes object without an exact operator grant must be rejected";
    }
    {
      assertion = !allAssertionsHold duplicateIdentityWorker;
      message = "differently named contributions must not target one Kubernetes object identity";
    }
    {
      assertion = !invalidNumericWorker.success;
      message = "Kubernetes object specs must reject non-integer JSON numbers";
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
    workerAddonRenderer = pkgs.k3s-worker.passthru.addonRenderer;
    inherit
      workerAddonsFile
      tamperedWorkerAddonsFile
      tamperedObjectAddonsFile
      floatingAddonsFile
      extendedWorkerAddonsFile
      ;

    phases = [
      {
        name = "check";
        script = ''
          : "$contract"

          for expose in "$workerExpose" "$controlPlaneExpose" "$combinedExpose"; do
            test -f "$expose/manifest.json"
            grep -q '"path":"/etc/aos/packages/k3s-' "$expose/manifest.json"
            grep -q '"name":"addons"' "$expose/manifest.json"
            grep -q '"required":\["resources","revision","role","schema"\]' "$expose/manifest.json"
            grep -q '"name":"token"' "$expose/manifest.json"
            grep -q '"source":"/run/credstore/k3s-[^"]*/token"' "$expose/manifest.json"
            grep -q '"encrypted":false' "$expose/manifest.json"
            grep -q 'EnvironmentFile=-/etc/aos/packages/k3s-' "$expose/units/k3s.service"
            grep -q 'ExecStart=.*/bin/k3s-k3s-' "$expose/units/k3s.service"
            grep -q 'ExecCondition=.*/bin/k3s-k3s-' "$expose/units/k3s.service"
            grep -q 'EnvironmentFile=-/etc/aos/packages/k3s-' "$expose/units/k3s-preflight.service"
            test "$(grep -c '^ExecCondition=' "$expose/units/k3s-preflight.service" || true)" -eq 0
          done

          renderer="$workerAddonRenderer/bin/k3s-worker-render-addons"
          "$renderer" "$workerAddonsFile/addons.json" rendered-a.yaml revision-a
          "$renderer" "$workerAddonsFile/addons.json" rendered-b.yaml revision-b

          cmp rendered-a.yaml rendered-b.yaml
          cmp revision-a revision-b
          test "$(cat revision-a)" = ${lib.escapeShellArg workerAddons.revision}
          grep -q '"apiVersion":"helm.cattle.io/v1"' rendered-a.yaml
          grep -q 'café/雪' rendered-a.yaml
          grep -q '"aboveBinary64ExactInteger":9007199254740993' rendered-a.yaml
          grep -q '"maximumI64":9223372036854775807' rendered-a.yaml
          grep -q '"minimumI64":-9223372036854775808' rendered-a.yaml
          test "$(grep -c 'aos.andyl.com/object-revision' rendered-a.yaml)" -eq 3
          test "$(grep -c '^---$' rendered-a.yaml)" -eq 3

          if "$renderer" "$tamperedWorkerAddonsFile/addons.json" rejected.yaml rejected.revision; then
            echo "tampered add-on revision was accepted" >&2
            exit 1
          fi

          if "$renderer" "$tamperedObjectAddonsFile/addons.json" rejected.yaml rejected.revision; then
            echo "tampered Kubernetes object revision was accepted" >&2
            exit 1
          fi

          if "$renderer" "$floatingAddonsFile/addons.json" rejected.yaml rejected.revision; then
            echo "non-integer JSON number was accepted" >&2
            exit 1
          fi

          if "$renderer" "$extendedWorkerAddonsFile/addons.json" rejected.yaml rejected.revision; then
            echo "extended add-on contract was accepted" >&2
            exit 1
          fi

          mkdir -p "$out"
          printf '%s\n' ok > "$out/result"
        '';
      }
    ];

    meta.description = "Typed k3s role configuration contract checks";
  }
