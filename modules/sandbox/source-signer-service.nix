##! modules/sandbox/source-signer-service.nix — separate Source-only hold signer
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.sourceSignerService;
  controller = config.aos.sandbox.controller;
  view = config.aos.sandbox.sourceSignerView;
  policy = config.aos.sandbox.policyAuthority;
in {
  options.aos.sandbox.sourceSignerService = {
    enable = lib.mkEnableOption "the separate, nonauthorizing Source-only hold signer";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "The package containing aos-sandbox-source-signerd.";
    };

    credentials = {
      seed = lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "Signer-private 32-byte Ed25519 Source-purpose seed.";
      };

      publicKey = lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "80-byte AOSSPK01 pin shared by name with the independently provisioned Root credential.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = view.enable && policy.enable && config.aos.sandbox.controllerService.enable;
        message = "Source signer requires its read-only view, Controller, and policy authority";
      }
      {
        assertion = cfg.credentials.seed != null && cfg.credentials.publicKey != null;
        message = "Source signer requires a separate private seed and public pin";
      }
      {
        assertion = cfg.credentials.publicKey == policy.credentials.sourceHoldPublicKey;
        message = "Source signer and Root policy authority must load the same independently provisioned Source pin";
      }
      {
        assertion = let
          service = config.systemd.services.aos-sandbox-source-signerd.serviceConfig;
        in
          (service.ProtectSystem or null)
          == "strict"
          && (service.CapabilityBoundingSet or null) == ""
          && (service.ReadWritePaths or []) == []
          && (service.BindPaths or []) == [];
        message = "Source signer must have no broad write path or capabilities";
      }
    ];

    systemd.sockets.aos-sandbox-source-signerd = {
      description = "AOS Source-only signer Root ingress";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-source-signer-view.service"];
      after = ["aos-sandbox-source-signer-view.service"];
      unitConfig.BindsTo = ["aos-sandbox-source-signer-view.service"];
      socketConfig = {
        ListenStream = "/run/aos/sandbox-source-signerd.sock";
        Service = "aos-sandbox-source-signerd.service";
        Accept = false;
        SocketUser = "aos-source-signer";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0660";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-source-signerd = {
      description = "AOS separate Source-only hold signer";
      requires = ["aos-sandbox-source-signer-view.service" "aos-sandbox-source-signerd.socket"];
      after = ["aos-sandbox-source-signer-view.service" "aos-sandbox-source-signerd.socket"];
      unitConfig.BindsTo = ["aos-sandbox-source-signer-view.service"];
      serviceConfig = {
        Type = "simple";
        Sockets = ["aos-sandbox-source-signerd.socket"];
        StandardInput = "socket";
        ExecStart = "${cfg.package}/bin/aos-sandbox-source-signerd ${toString controller.uid} ${toString controller.gid} ${toString view.uid} ${toString view.gid}";
        LoadCredential =
          lib.optionals (cfg.credentials.seed != null) ["source-hold-signing-seed:/run/credentials/@system/${cfg.credentials.seed}"]
          ++ lib.optionals (cfg.credentials.publicKey != null) ["source-hold-public-key:/run/credentials/@system/${cfg.credentials.publicKey}"];
        User = "aos-source-signer";
        Group = "aos-source-signer";
        UMask = "0077";

        CapabilityBoundingSet = "";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = ["AF_UNIX"];
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
      };
    };
  };
}
