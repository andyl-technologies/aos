# modules/monitoring/node-exporter.nix — Prometheus node exporter module
#
# Configures the Prometheus node_exporter for hardware and OS metrics.
# Generates a systemd service with the appropriate collector flags.
# The node exporter exposes metrics at http://<host>:<port>/metrics in
# Prometheus exposition format.
#
# Absorbed TOML config values:
#   [monitoring.node_exporter] enable, port, listen_address
#   [monitoring.node_exporter] enabled_collectors, disabled_collectors

{ config, pkgs, lib, ... }:

let
  cfg = config.aos.monitoring.nodeExporter;

  # Build the --collector.* and --no-collector.* flags.
  enabledFlags = builtins.map (c: "--collector.${c}") cfg.enabledCollectors;
  disabledFlags = builtins.map (c: "--no-collector.${c}") cfg.disabledCollectors;

  # Complete command-line flags.
  nodeExporterFlags = builtins.concatStringsSep " " ([
    "--web.listen-address=${cfg.listenAddress}:${toString cfg.port}"
    "--path.procfs=/proc"
    "--path.sysfs=/sys"
    "--path.rootfs=/"
  ] ++ enabledFlags ++ disabledFlags);

in
{
  options.aos.monitoring.nodeExporter = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the Prometheus node_exporter. Exposes hardware and OS
        metrics (CPU, memory, disk, network, systemd unit status) for
        scraping by a Prometheus server.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 9100;
      description = "TCP port for the node exporter metrics endpoint.";
    };

    enabledCollectors = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "cpu"
        "diskstats"
        "filesystem"
        "loadavg"
        "meminfo"
        "netdev"
        "stat"
        "time"
        "uname"
        "systemd"
      ];
      description = ''
        List of node_exporter collectors to enable. The defaults cover
        the essential system metrics for server monitoring. The "systemd"
        collector exposes unit status, which is valuable for alerting on
        failed services.
      '';
    };

    disabledCollectors = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        List of node_exporter collectors to explicitly disable. Use this
        to suppress collectors that produce excessive cardinality or are
        not relevant to the workload.
      '';
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0";
      description = ''
        Address to listen on for the metrics endpoint. Use "0.0.0.0" to
        listen on all interfaces or "127.0.0.1" to restrict to localhost.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.node-exporter ];

    # node-exporter.service — Prometheus node metrics exporter.
    systemd.services."node-exporter" = {
      description = "Prometheus Node Exporter";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "/usr/bin/node_exporter ${nodeExporterFlags}";
        Restart = "on-failure";
        RestartSec = "5s";
        # Run as a dedicated unprivileged user.
        DynamicUser = true;
        User = "node-exporter";
        Group = "node-exporter";
        # Security hardening — node_exporter only reads /proc, /sys, /.
        ProtectSystem = "full";
        ProtectHome = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ReadOnlyPaths = [ "/" ];
        # Allow access to /proc and /sys for metrics collection.
        ProtectKernelTunables = false;
        ProtectKernelModules = true;
        ProtectControlGroups = false;
        # Resource limits.
        MemoryMax = "128M";
        CPUQuota = "25%";
      };
    };

    # Open the node exporter port in the firewall.
    aos.firewall.allowedTCP = [ 22 cfg.port ];
  };
}
