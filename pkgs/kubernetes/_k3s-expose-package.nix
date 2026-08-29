{
  lib,
  mkDerivation,
  k3s,
  containerd,
  runc,
  cni-plugins,
  iptables,
  ipset,
  conntrack-tools,
  socat,
  ethtool,
  iproute2,
  util-linux,
  kmod,
  coreutils,
  jq,
  writeShellScriptBin,
}: let
  pkgs = {
    inherit
      k3s
      containerd
      runc
      cni-plugins
      iptables
      ipset
      conntrack-tools
      socat
      ethtool
      iproute2
      util-linux
      kmod
      coreutils
      jq
      writeShellScriptBin
      ;
  };
  common = import ./_k3s-common.nix {inherit lib pkgs;};
in
  {
    pname,
    role,
    description,
    command,
    requiredEnv,
    firewall,
    stateDirectories ? ["rancher/k3s" "kubelet"],
    hostPaths ? [
      {
        path = "/var/lib/rancher";
        mode = "rw";
      }
      {
        path = "/var/lib/kubelet";
        mode = "rw";
      }
      {
        path = "/etc/rancher/k3s";
        mode = "rw";
      }
      {
        path = "/etc/rancher/node";
        mode = "rw";
      }
      {
        path = "/lib/modules";
        mode = "read-only";
      }
    ],
    prepareHostPathDirectories ?
      builtins.map (hostPath: hostPath.path) (
        builtins.filter (hostPath: hostPath.mode == "rw") hostPaths
      ),
  }: let
    stateDirectoryText = builtins.concatStringsSep " " stateDirectories;
    launcher = common.launcher pname command;
    enabledCheck = common.enabledCheck pname;
    configFields = [
      "K3S_ENABLED"
      "K3S_URL"
      "K3S_NODE_NAME"
      "K3S_NODE_IP"
      "K3S_NODE_EXTERNAL_IP"
      "K3S_NODE_LABEL"
      "K3S_NODE_TAINT"
      "K3S_FLANNEL_BACKEND"
      "K3S_FLANNEL_IFACE"
      "K3S_CLUSTER_CIDR"
      "K3S_SERVICE_CIDR"
      "K3S_CLUSTER_DNS"
      "K3S_DISABLE_NETWORK_POLICY"
      "K3S_DISABLE_KUBE_PROXY"
      "K3S_CLUSTER_INIT"
      "K3S_DISABLE"
      "K3S_TLS_SAN"
      "K3S_KUBECONFIG_MODE"
    ];
  in
    mkDerivation {
      inherit pname;
      inherit (k3s) version;
      src = null;
      runtimeDeps = common.runtimePath;

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/${pname}"
            printf '%s\n' ${lib.escapeShellArg pname} > "$out/share/${pname}/payload.txt"
            printf '%s\n' ${lib.escapeShellArg (builtins.toJSON {inherit pname role;})} > "$out/share/k3s-role.json"
          '';
        }
      ];

      expose = {
        units = {
          "k3s-preflight.service" =
            common.preflightService pname requiredEnv;

          "k3s.service" = {
            inherit description;
            after = ["network-online.target" "k3s-preflight.service"];
            wants = ["network-online.target"];
            requisite = ["k3s-preflight.service"];
            path = common.runtimePath;
            serviceConfig = {
              Type = "notify";
              EnvironmentFile = "-/etc/aos/packages/${pname}/k3s.env";
              ExecCondition = "${enabledCheck}/bin/k3s-${pname}-enabled";
              ExecStart = "${launcher}/bin/k3s-${pname}-start";
              KillMode = "process";
              Delegate = "yes";
              StateDirectory = stateDirectoryText;
              LimitNOFILE = "1048576";
              LimitNPROC = "infinity";
              LimitCORE = "infinity";
              TasksMax = "infinity";
              TimeoutStartSec = "infinity";
              Restart = "always";
              RestartSec = "5s";
            };
          };
        };

        config = {
          artifacts = [
            {
              name = "env";
              path = "/etc/aos/packages/${pname}/k3s.env";
              format = "env";
              required = [];
              optional = configFields;
              units = ["k3s-preflight.service" "k3s.service"];
              reload = "restart";
            }
            {
              name = "addons";
              path = "/etc/aos/packages/${pname}/addons.json";
              format = "json";
              required = ["resources" "schema"];
              units = ["k3s.service"];
              reload = "restart";
            }
          ];
          credentials = [
            {
              name = "token";
              source = "/run/credstore/${pname}/token";
              units = ["k3s.service"];
              encrypted = false;
            }
          ];
        };

        kernel = {
          modules = common.kernelModules;
          sysctl = common.sysctls;
        };

        inherit firewall;
        inherit prepareHostPathDirectories;

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
          devices = [
            "/dev/net/tun"
            "/dev/kmsg"
            "/dev/fuse"
          ];
          host-paths = hostPaths;
          kernel-modules = common.kernelModules;
          syscalls = "privileged";
          security-label = "aos-pkg-${pname}";
        };
      };

      configModule = {
        src = ./_k3s-config;
        moduleAbiCompat = {
          min = 1;
          max = 2;
        };
        declares = [
          "k3s.enable"
          "k3s.integrations.cni"
          "k3s.integrations.csi"
          "k3s.integrations.resources"
          "k3s.kubeconfigMode"
          "k3s.networking.clusterCidr"
          "k3s.networking.clusterDns"
          "k3s.networking.disableKubeProxy"
          "k3s.networking.disableNetworkPolicy"
          "k3s.networking.flannelBackend"
          "k3s.networking.flannelInterface"
          "k3s.networking.serviceCidr"
          "k3s.node.externalIp"
          "k3s.node.ip"
          "k3s.node.labels"
          "k3s.node.name"
          "k3s.node.taints"
          "k3s.role"
          "k3s.server.clusterInit"
          "k3s.server.disableComponents"
          "k3s.server.tlsSans"
          "k3s.serverUrl"
          "k3s.token"
        ];
        ownsRoots = [
          {
            root = "k3s";
            interfaceAbi = 2;
            contributable = [
              "integrations.cni"
              "integrations.csi"
              "integrations.resources"
            ];
          }
        ];
      };

      meta = {
        description = "AOS exposed ${description} package";
        license = "Apache-2.0";
      };
    }
