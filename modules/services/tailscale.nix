##! modules/services/tailscale.nix — Tailscale mesh VPN service
##!
##! Runs tailscaled with persistent node identity under /var/lib/tailscale and
##! its local API socket under /run/tailscale. Enrollment remains an explicit
##! operator action through the tailscale up command.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.tailscale;
  extraArgs = lib.concatMapStringsSep " " lib.escapeShellArg cfg.extraArgs;
in {
  options.aos.services.tailscale = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run the Tailscale mesh VPN daemon.";
    };

    port = lib.mkOption {
      type = lib.types.int;
      default = 41641;
      description = "UDP port used for direct WireGuard peer connections.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Additional command-line arguments passed to tailscaled.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.port >= 0 && cfg.port <= 65535;
        message = "aos.services.tailscale.port must be between 0 and 65535";
      }
    ];

    environment.systemPackages = [
      pkgs.tailscale
      pkgs.getent
      pkgs.iproute2
      pkgs.iptables
      pkgs.procps-ng
    ];

    environment.etc."tmpfiles.d/aos-tailscale.conf".text = ''
      d /run/tailscale 0755 root root - -
      d /var/lib/tailscale 0700 root root - -
    '';

    systemd.services.tailscaled = {
      description = "Tailscale mesh VPN daemon";
      wantedBy = ["multi-user.target"];
      after = ["network-pre.target" "systemd-tmpfiles-setup.service"];
      wants = ["network-pre.target"];
      requires = ["systemd-tmpfiles-setup.service"];
      serviceConfig = {
        Type = "notify";
        ExecStart =
          "${pkgs.tailscale}/bin/tailscaled"
          + " --state=/var/lib/tailscale/tailscaled.state"
          + " --socket=/run/tailscale/tailscaled.sock"
          + " --port=${toString cfg.port}"
          + lib.optionalString (extraArgs != "") " ${extraArgs}";
        ExecStopPost = "${pkgs.tailscale}/bin/tailscaled --cleanup";
        Restart = "on-failure";
        RuntimeDirectory = "tailscale";
        RuntimeDirectoryMode = "0755";
        StateDirectory = "tailscale";
        StateDirectoryMode = "0700";
        Environment = "PATH=${lib.makeBinPath [pkgs.getent pkgs.iproute2 pkgs.iptables pkgs.procps-ng]}";
        CapabilityBoundingSet = ["CAP_NET_ADMIN" "CAP_NET_RAW"];
        AmbientCapabilities = ["CAP_NET_ADMIN" "CAP_NET_RAW"];
        DeviceAllow = ["/dev/net/tun rw"];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ReadWritePaths = ["/run/tailscale" "/var/lib/tailscale"];
      };
    };

    system.checks.tailscale = {
      description = "Tailscale service checks";
      checks = [
        {
          name = "tailscaled-active";
          description = "tailscaled reaches its ready state";
          script = ''
            vm.wait_until_succeeds(
                "systemctl is-active --quiet tailscaled.service", timeout=30
            )
          '';
        }
        {
          name = "tailscale-local-api";
          description = "tailscaled creates its protected local API socket";
          script = ''
            vm.succeed("test -S /run/tailscale/tailscaled.sock")
            vm.succeed(
                "tailscale --socket=/run/tailscale/tailscaled.sock debug prefs "
                "| grep -F '\"LoggedOut\": true'"
            )
          '';
        }
      ];
    };
  };
}
