##! modules/kubernetes/node-problem-detector.nix — Node Problem Detector module
##!
##! Configures the Kubernetes Node Problem Detector (NPD), a daemon that
##! monitors node health and reports conditions to the Kubernetes API server.
##! NPD detects hardware issues, kernel deadlocks, container runtime problems,
##! and other node-level failures that kubelet alone cannot detect. It exposes
##! a health endpoint for monitoring and integrates with Kubernetes node
##! conditions and events.
##!
##! Options:
##!   [kubernetes.nodeProblemDetector] enable, port

{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.aos.kubernetes.nodeProblemDetector;

in
{
  options.aos.kubernetes.nodeProblemDetector = {
    ## Enable the Kubernetes Node Problem Detector (NPD).
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the Kubernetes Node Problem Detector (NPD). Monitors
        node health conditions including hardware errors, kernel panics,
        container runtime issues, and filesystem corruption. Reports
        problems as Kubernetes node conditions and events.
      '';
    };

    ## TCP port for the NPD health and metrics endpoint.
    port = lib.mkOption {
      type = lib.types.port;
      default = 20256;
      description = ''
        TCP port for the Node Problem Detector health and metrics
        endpoint. This port is also opened in the firewall when
        NPD is enabled.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.node-problem-detector ];

    # node-problem-detector.service — Kubernetes node health monitor.
    systemd.services."node-problem-detector" = {
      description = "Kubernetes Node Problem Detector";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network-online.target"
        "kubelet.service"
      ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = builtins.concatStringsSep " " [
          "${pkgs.node-problem-detector}/bin/node-problem-detector"
          "--port=${toString cfg.port}"
          "--logtostderr"
          "--system-log-monitors=/etc/node-problem-detector.d/kernel-monitor.json"
          "--custom-plugin-monitors=/etc/node-problem-detector.d/health-checker.json"
        ];
        Restart = "on-failure";
        RestartSec = "10s";
        # Security hardening — NPD needs access to system logs and /proc.
        ProtectHome = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectKernelModules = true;
        # NPD needs to read kernel logs and /proc for health checks.
        ProtectKernelTunables = false;
        ProtectControlGroups = false;
        # Resource limits.
        MemoryMax = "256M";
        CPUQuota = "25%";
      };
    };

    # Kernel log monitor configuration.
    environment.etc."node-problem-detector.d/kernel-monitor.json" = {
      text = builtins.toJSON {
        plugin = "kmsg";
        logPath = "/dev/kmsg";
        lookback = "5m";
        bufferSize = 10;
        source = "kernel-monitor";
        conditions = [
          {
            type = "KernelDeadlock";
            reason = "KernelHasNoDeadlock";
            message = "kernel has no deadlock";
          }
          {
            type = "ReadonlyFilesystem";
            reason = "FilesystemIsNotReadOnly";
            message = "Filesystem is not read-only";
          }
        ];
        rules = [
          {
            type = "temporary";
            reason = "OOMKilling";
            pattern = "Kill process \\d+ (.+) score \\d+ or sacrifice child\\nKilled process \\d+ (.+)";
          }
          {
            type = "temporary";
            reason = "TaskHung";
            pattern = "task \\S+ blocked for more than \\d+ seconds";
          }
          {
            type = "permanent";
            condition = "KernelDeadlock";
            reason = "AUFSUmountHung";
            pattern = "task umount\\.aufs:\\w+ blocked for more than \\d+ seconds";
          }
        ];
      };
    };

    # Health checker plugin configuration.
    environment.etc."node-problem-detector.d/health-checker.json" = {
      text = builtins.toJSON {
        plugin = "custom";
        pluginConfig = {
          invoke_interval = "30s";
          timeout = "10s";
          max_output_length = 80;
        };
        source = "health-checker";
        conditions = [
          {
            type = "ContainerRuntimeUnhealthy";
            reason = "ContainerRuntimeIsHealthy";
            message = "Container runtime is healthy";
          }
        ];
        rules = [
          {
            type = "permanent";
            condition = "ContainerRuntimeUnhealthy";
            reason = "ContainerdUnhealthy";
            path = "${pkgs.bash}/bin/sh";
            args = [
              "-c"
              "test -S /run/containerd/containerd.sock"
            ];
            timeout = "10s";
          }
        ];
      };
    };

    # Ensure NPD configuration directory exists.
    environment.etc."tmpfiles.d/aos-node-problem-detector.conf" = {
      text = ''
        # Node Problem Detector configuration directory.
        d /etc/node-problem-detector.d 0755 root root -
      '';
    };

    # Open the NPD health/metrics port in the firewall.
    aos.firewall.allowedTCP = [
      22
      cfg.port
    ];
  };
}
