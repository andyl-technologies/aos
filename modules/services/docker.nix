##! modules/services/docker.nix — Docker container engine service
##!
##! Runs the source-built Docker daemon with persistent graph storage under
##! `/var/lib/docker` and its local API socket under `/run/docker.sock`.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.docker;
  extraOptions = lib.concatMapStringsSep " " lib.escapeShellArg cfg.extraOptions;
in {
  options.aos.services.docker = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run the Docker container engine.";
    };

    dataRoot = lib.mkOption {
      type = lib.types.strMatching "/[A-Za-z0-9._+/-]+";
      default = "/var/lib/docker";
      description = "Absolute directory used for persistent Docker data.";
    };

    storageDriver = lib.mkOption {
      type = lib.types.enum ["overlay2" "btrfs" "fuse-overlayfs"];
      default = "overlay2";
      description = "Storage driver used for container layers.";
    };

    liveRestore = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Keep containers running while the daemon is unavailable.";
    };

    extraOptions = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Additional command-line options passed to dockerd.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [pkgs.docker];

    environment.etc."tmpfiles.d/aos-docker.conf".text = ''
      d /run/docker 0755 root root - -
      d ${cfg.dataRoot} 0710 root root - -
    '';

    systemd.services.docker = {
      description = "Docker container engine";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target" "systemd-tmpfiles-setup.service"];
      wants = ["network-online.target"];
      requires = ["systemd-tmpfiles-setup.service"];
      serviceConfig = {
        Type = "notify";
        ExecStart =
          "${pkgs.docker-engine}/bin/dockerd"
          + " --host=unix:///run/docker.sock"
          + " --data-root=${lib.escapeShellArg cfg.dataRoot}"
          + " --exec-root=/run/docker"
          + " --pidfile=/run/docker/docker.pid"
          + " --group=root"
          + " --storage-driver=${cfg.storageDriver}"
          + lib.optionalString cfg.liveRestore " --live-restore"
          + lib.optionalString (extraOptions != "") " ${extraOptions}";
        ExecReload = "${pkgs.coreutils}/bin/kill -s HUP $MAINPID";
        Restart = "on-failure";
        RestartSec = "2s";
        Delegate = true;
        KillMode = "process";
        OOMScoreAdjust = -500;
        LimitNOFILE = "infinity";
        LimitNPROC = "infinity";
        TasksMax = "infinity";
      };
    };

    system.checks.docker = {
      description = "Docker service checks";
      checks = [
        {
          name = "docker-active";
          description = "Docker reaches its ready state";
          script = ''
            vm.wait_until_succeeds(
                "systemctl is-active --quiet docker.service", timeout=60
            )
          '';
        }
        {
          name = "docker-api";
          description = "The Docker CLI reaches the local daemon and plugins";
          script = ''
            vm.succeed("docker version --format '{{.Server.Version}}'")
            vm.succeed("docker info --format '{{.Driver}}' | grep -Fx '${cfg.storageDriver}'")
            vm.succeed("docker buildx version")
            vm.succeed("docker compose version")
          '';
        }
      ];
    };
  };
}
