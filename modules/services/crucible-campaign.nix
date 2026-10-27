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
  cfg = config.aos.crucibleCampaign;
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
  command = executable: arguments: {
    executable = {
      path = executable;
      inherit arguments;
    };
    ignore_failure = false;
  };
  campaignService = {
    service = "crucible-campaign";
    lifecycle = {
      description = "Crucible campaign and lifecycle service";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      # A socket left by an unclean exit would make the bind fail.
      pre_start = [(command "${pkgs.coreutils}/bin/rm" ["-f" cfg.socketPath])];
      start = [
        (command "${pkgs.crucible}/bin/crucible" [
          "serve"
          "--listen"
          cfg.listenAddress
          "--trusted-unauthenticated-bind"
          "--campaign-socket"
          cfg.socketPath
          "--campaign-state"
          cfg.stateDirectory
          "--campaign-policy"
          "/etc/crucible/campaign-policy.toml"
          "--campaign-socket-mode"
          "600"
        ])
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 1000;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [];
      before = [];
      requires = [];
      wants = [];
      prerequisites = [];
    };
    # Both directories stay owner-only; the socket inherits its directory.
    directories.managed = [
      {
        path = lib.removePrefix "/var/lib/" cfg.stateDirectory;
        purpose = "state";
        mode = "0700";
        retention = "persistent";
        owner = "root";
        group = "root";
      }
      {
        path = lib.removePrefix "/run/" (builtins.dirOf cfg.socketPath);
        purpose = "runtime";
        mode = "0700";
        retention = "restart";
        owner = "root";
        group = "root";
      }
    ];
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "shared";
      devices = [];
      host_paths = [];
      permit_core_dumps = true;
    };
  };
in {
  # Feature settings live in their own namespace, declared in every evaluation
  # stage. The shared aos.services entry below carries only the service model,
  # whose declarations exist once the service-management package is loaded.
  options.aos.crucibleCampaign = {
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
      # Like other package services, the entry is declared unconditionally and
      # its enable flag alone selects deployment.
      aos.services."crucible-campaign" = lib.mkMerge [
        (lib.mkDefault campaignService)
        {enable = lib.mkDefault cfg.enable;}
      ];

      assertions = [
        {
          assertion = listenPort > 0 && listenPort <= 65535;
          message = "aos.crucibleCampaign.listenAddress must be a numeric loopback address with a valid nonzero TCP port";
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
          message = "aos.crucibleCampaign.socketPath must be a normalized file below /run/crucible-campaign";
        }
        {
          assertion = stateDirectoryIsOwned;
          message = "aos.crucibleCampaign.stateDirectory must be a normalized path at or below /var/lib/crucible-campaign";
        }
      ];

      environment.etc."crucible/campaign-runtime.env".text = ''
        schema=aos.crucible.campaign-runtime.v1
        enabled=${
          if cfg.enable
          then "true"
          else "false"
        }
        identity=${runtimeIdentity}
        listen_address=${cfg.listenAddress}
        socket_path=${cfg.socketPath}
        state_directory=${cfg.stateDirectory}
      '';
    }
    (lib.mkIf cfg.enable {
      environment.systemPackages = [pkgs.crucible];
      # Bootstrap authenticates the policy inode and refuses symlinks.
      environment.etc."crucible/campaign-policy.toml".mode = "0444";
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
    })
  ];
}
