##! kubelet — Kubernetes node agent
{
  lib,
  mkGoPackage,
  kubeSource,
  bash,
  writeShellScriptBin,
}: let
  launcher = writeShellScriptBin "kubelet-start" ''
    set -eu
    args=(
      --config=/etc/aos/packages/kubelet/config.json
      --root-dir=/var/lib/kubelet
      --hostname-override="$KUBELET_NODE_NAME"
    )
    if [ -e /run/credentials/kubelet.service/kubeconfig ]; then
      args+=(--kubeconfig=/run/credentials/kubelet.service/kubeconfig)
    fi
    exec /bin/kubelet "''${args[@]}"
  '';
in
  mkGoPackage {
    pname = "kubelet";
    inherit (kubeSource) version src;

    goPackage = "./cmd/kubelet";
    goOutput = "kubelet";
    ldflags = "-s -w -X k8s.io/component-base/version.gitVersion=v${kubeSource.version}";
    doCheck = false;
    runtimeDeps = [bash launcher];

    expose = {
      units."kubelet.service" = {
        description = "Standalone Kubernetes node agent";
        after = ["network-online.target" "containerd.service"];
        wants = ["network-online.target"];
        restartIfChanged = true;
        stopOnRemoval = true;
        path = [bash];
        serviceConfig = {
          Type = "notify";
          EnvironmentFile = "/etc/aos/packages/kubelet/runtime.env";
          ExecCondition = "${bash}/bin/bash -c 'test \"$KUBELET_ENABLED\" = true'";
          ExecStart = "${launcher}/bin/kubelet-start";
          Restart = "always";
          RestartSec = "5s";
          Delegate = true;
          KillMode = "process";
          StateDirectory = "kubelet";
          RuntimeDirectory = "kubelet";
          LogsDirectory = "pods";
          LimitNOFILE = 1048576;
          LimitNPROC = "infinity";
          LimitCORE = "infinity";
          TasksMax = "infinity";
        };
      };
      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/kubelet/runtime.env";
            format = "env";
            required = [
              "KUBELET_ENABLED"
              "KUBELET_NODE_NAME"
            ];
            units = ["kubelet.service"];
            reload = "restart";
          }
          {
            name = "config";
            path = "/etc/aos/packages/kubelet/config.json";
            format = "json";
            required = ["apiVersion" "kind" "address" "containerRuntimeEndpoint"];
            optional = [
              "authentication"
              "authorization"
              "cgroupDriver"
              "clusterDNS"
              "clusterDomain"
              "failSwapOn"
              "maxPods"
              "port"
              "readOnlyPort"
              "registerNode"
              "staticPodPath"
            ];
            units = ["kubelet.service"];
            reload = "restart";
          }
        ];
        credentials = [
          {
            name = "kubeconfig";
            source = "/run/credstore/kubelet/kubeconfig";
            units = ["kubelet.service"];
            encrypted = false;
            optional = true;
          }
        ];
      };
      prepareHostPathDirectories = [
        "/var/lib/kubelet"
        "/var/log/pods"
      ];
      permissions = {
        network = "host";
        privileged-users = true;
        cgroup-delegate = true;
        capabilities = [
          "CAP_SYS_ADMIN"
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_SYS_RESOURCE"
          "CAP_SYS_PTRACE"
        ];
        devices = ["/dev/kmsg" "/dev/null" "/dev/random" "/dev/urandom"];
        host-paths = [
          {
            path = "/var/lib/kubelet";
            mode = "rw";
          }
          {
            path = "/var/log/pods";
            mode = "rw";
          }
          {
            path = "/run/containerd";
            mode = "rw";
          }
          {
            path = "/sys/fs/cgroup";
            mode = "rw";
          }
        ];
        kernel-modules = ["br_netfilter" "overlay"];
        syscalls = "privileged";
        security-label = "aos-pkg-kubelet";
      };
      kernel.modules = ["br_netfilter" "overlay"];
      firewall = {
        allowedTCP = [10250];
        allowedUDP = [];
      };
    };

    configModule = {
      src = ./_kubelet-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "kubelet.address"
        "kubelet.authentication.anonymous"
        "kubelet.cgroupDriver"
        "kubelet.clusterDns"
        "kubelet.clusterDomain"
        "kubelet.enable"
        "kubelet.failSwapOn"
        "kubelet.kubeconfig"
        "kubelet.maxPods"
        "kubelet.nodeName"
        "kubelet.registerNode"
        "kubelet.runtimeEndpoint"
        "kubelet.staticPodPath"
      ];
      ownsRoots = [
        {
          root = "kubelet";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = ["aos/packages/kubelet/config.json"];
        units = [];
        users = [];
        groups = [];
      };
      documentation = {
        summary = "kubelet — Kubernetes node agent that manages pods";
        sections = {
          deployment = lib.aosDoc.section "Standalone node agent" [
            (lib.aosDoc.paragraph "Use this package when kubelet is managed independently. K3s roles embed and configure their own node agent and do not enable this service.")
            (lib.aosDoc.paragraph "When node registration is disabled, the generated kubelet configuration also disables API-server webhook authentication and selects local AlwaysAllow authorization so static-pod-only operation does not require an API client.")
          ];
          credentials = lib.aosDoc.section "Control-plane identity" [
            (lib.aosDoc.paragraph "The optional kubeconfig is an opaque credential reference delivered only to kubelet. Static-pod-only deployments may leave it unset and disable node registration.")
          ];
          privilege = lib.aosDoc.section "Host authority" [
            (lib.aosDoc.note "security" [
              (lib.aosDoc.paragraph "Kubelet is root-equivalent: it controls containers, cgroups, mounts, devices, and host networking. Install and enable it only on nodes dedicated to this trust boundary.")
            ])
          ];
        };
      };
    };

    checks = {
      testing,
      self,
      pkgs,
    }: let
      evaluated = lib.evalModules {
        inherit lib;
        modules = [
          ({lib, ...}: {
            options = {
              assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
              };
              kubelet.config = lib.mkOption {
                type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                default = {};
              };
              kubelet.credentials = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
              environment.etc = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
            };
          })
          ./_kubelet-config/module.nix
          {
            kubelet = {
              enable = true;
              nodeName = "worker-a";
              registerNode = true;
              kubeconfig.ref = "system-credential:kubelet-worker-a";
              maxPods = 80;
            };
          }
        ];
      };
    in {
      version = testing.mkToolCheck {
        pname = "tool-kubelet";
        tool = self;
        command = "kubelet --version";
      };
      config-module-contract = pkgs.runCommand "kubelet-config-module-contract" {} ''
              config=${builtins.toFile "kubelet.json" (builtins.toJSON evaluated.config.kubelet.config.config)}
        ${pkgs.jq}/bin/jq -e '
          .apiVersion == "kubelet.config.k8s.io/v1beta1"
          and .maxPods == 80
                and .containerRuntimeEndpoint == "unix:///run/containerd/containerd.sock"
            ' "$config" >/dev/null
          set +e
          ${pkgs.coreutils}/bin/timeout 5 \
          ${self}/bin/kubelet --config="$config" \
            >"$TMPDIR/kubelet.log" 2>&1
          status=$?
          set -e
          test "$status" -ne 0
          if ${pkgs.grep}/bin/grep -E 'failed to (load|parse)|strict decoding error|unknown field' \
            "$TMPDIR/kubelet.log"; then
            cat "$TMPDIR/kubelet.log" >&2
            exit 1
          fi
            test '${evaluated.config.kubelet.config.runtime.KUBELET_NODE_NAME}' = worker-a
                test '${evaluated.config.kubelet.credentials.kubeconfig.ref}' = system-credential:kubelet-worker-a
                touch "$out"
      '';
    };

    meta = {
      description = "kubelet — Kubernetes node agent that manages pods";
      homepage = "https://kubernetes.io";
      license = "Apache-2.0";
    };
  }
