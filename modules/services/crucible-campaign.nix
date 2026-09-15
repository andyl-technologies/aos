##! Production Crucible campaign service composition.
##!
##! The option is disabled by default. Enabled systems expose the packaged
##! campaign service through its owner-only Unix socket and public CLI. Both
##! modes publish a non-secret immutable runtime identity so release gates can
##! bind observations to the exact evaluated system configuration.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.crucibleCampaign;
  listenPrefix =
    if lib.hasPrefix "127.0.0.1:" cfg.listenAddress
    then "127.0.0.1:"
    else if lib.hasPrefix "[::1]:" cfg.listenAddress
    then "[::1]:"
    else "";
  listenPortText =
    builtins.substring
    (builtins.stringLength listenPrefix)
    (builtins.stringLength cfg.listenAddress)
    cfg.listenAddress;
  listenPortMatch = builtins.match "[1-9][0-9]{0,4}" listenPortText;
  listenPort =
    if listenPrefix != "" && listenPortMatch != null
    then builtins.fromJSON listenPortText
    else 0;
  hasNoControlCharacters = value: builtins.match "[^[:cntrl:]]*" value != null;
  socketPathIsOwned =
    builtins.match
    "/run/crucible-campaign/[A-Za-z0-9][A-Za-z0-9._-]*"
    cfg.socketPath
    != null;
  stateDirectoryIsOwned =
    builtins.match
    "/var/lib/crucible-campaign(/[A-Za-z0-9][A-Za-z0-9._-]*)*"
    cfg.stateDirectory
    != null;
  runtimeIdentity = builtins.hashString "sha256" (builtins.toJSON {
    schema = "aos.crucible.campaign-runtime.v1";
    inherit (cfg) enable listenAddress socketPath stateDirectory;
  });
in {
  options.aos.services.crucibleCampaign = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the packaged local Crucible campaign service.";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:18080";
      description = "Trusted loopback API address for the Crucible daemon.";
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/crucible-campaign/service.sock";
      description = "Owner-only Unix socket for the local campaign service.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/crucible-campaign";
      description = "Durable local campaign object and reference store.";
    };

    _runtimeIdentity = lib.mkOption {
      type = lib.types.str;
      default = runtimeIdentity;
      internal = true;
      readOnly = true;
      description = "Evaluated identity of the campaign runtime configuration.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = listenPort > 0 && listenPort <= 65535;
          message = "aos.services.crucibleCampaign.listenAddress must be a numeric loopback address with a valid nonzero TCP port";
        }
        {
          assertion = builtins.all hasNoControlCharacters [
            cfg.listenAddress
            cfg.socketPath
            cfg.stateDirectory
          ];
          message = "Crucible campaign runtime values must not contain control characters";
        }
        {
          assertion = socketPathIsOwned;
          message = "aos.services.crucibleCampaign.socketPath must be a normalized file below /run/crucible-campaign";
        }
        {
          assertion = stateDirectoryIsOwned;
          message = "aos.services.crucibleCampaign.stateDirectory must be a normalized path at or below /var/lib/crucible-campaign";
        }
      ];

      environment.etc."crucible/campaign-runtime.env".text = ''
        schema=aos.crucible.campaign-runtime.v1
        enabled=${if cfg.enable then "true" else "false"}
        identity=${runtimeIdentity}
        listen_address=${cfg.listenAddress}
        socket_path=${cfg.socketPath}
        state_directory=${cfg.stateDirectory}
      '';
    }
    (lib.mkIf cfg.enable {
      environment.systemPackages = [pkgs.crucible];
      environment.etc."crucible/campaign-policy.toml".text = ''
        schema = "crucible.campaign-local-policy"
        version = 1

        [[bindings]]
        user_id = 0
        group_id = 0
        principal = "operator"

        [[grants]]
        principal = "operator"
        operation = "list-campaigns"
        campaign = "*"

        [[grants]]
        principal = "operator"
        operation = "get-campaign"
        campaign = "*"

        [[grants]]
        principal = "operator"
        operation = "create-campaign"
        campaign = "*"

        [[grants]]
        principal = "operator"
        operation = "attach-campaign-runtime"
        campaign = "*"
      '';

      systemd.services.crucible-campaign = {
        description = "Crucible campaign and lifecycle service";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target"];
        serviceConfig = {
          Type = "simple";
          Restart = "on-failure";
          RestartSec = 1;
        };
        preStart = ''
          ${pkgs.coreutils}/bin/mkdir -p \
            ${lib.escapeShellArg cfg.stateDirectory} \
            ${lib.escapeShellArg (builtins.dirOf cfg.socketPath)}
          ${pkgs.coreutils}/bin/chmod 700 \
            ${lib.escapeShellArg cfg.stateDirectory} \
            ${lib.escapeShellArg (builtins.dirOf cfg.socketPath)}
          ${pkgs.coreutils}/bin/rm -f ${lib.escapeShellArg cfg.socketPath}
        '';
        script = ''
          exec ${pkgs.crucible}/bin/crucible serve \
            --listen ${lib.escapeShellArg cfg.listenAddress} \
            --trusted-unauthenticated-bind \
            --campaign-socket ${lib.escapeShellArg cfg.socketPath} \
            --campaign-state ${lib.escapeShellArg cfg.stateDirectory} \
            --campaign-policy /etc/crucible/campaign-policy.toml \
            --campaign-socket-mode 600
        '';
      };
    })
  ];
}
