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
      writeShellScriptBin
      ;
  };
  common = import ./_k3s-common.nix {inherit lib pkgs;};
in
  {
    pname,
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
              EnvironmentFile = "/etc/rancher/k3s/k3s.env";
              ExecStart = "${k3s}/bin/k3s ${command}";
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

      meta = {
        description = "AOS exposed ${description} package";
        license = "Apache-2.0";
      };
    }
