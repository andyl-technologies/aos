##! modules/sandbox/cache-signer-service.nix — separate Cache-only readback signer
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.cacheSignerService;
  controller = config.aos.sandbox.controller;
  views = config.aos.sandbox.cacheSignerView;
  policy = config.aos.sandbox.policyAuthority;
  controllerService = config.aos.sandbox.controllerService;
in {
  options.aos.sandbox.cacheSignerService = {
    enable = lib.mkEnableOption "the separate, nonauthorizing Cache-only readback signer";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "The package containing aos-sandbox-cache-signerd.";
    };

    credentials = {
      seed = lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "Signer-private 32-byte Ed25519 seed, distinct from the Controller diagnostic seed.";
      };

      publicKey = lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "80-byte AOSCPK01 pin shared by name with the independently provisioned root credential.";
      };

      memoryCeiling = lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "Signer-private AOSCSM01 physical heap ceiling; all other limits come from protected Cache quotas.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = views.enable && controllerService.enable && policy.enable;
        message = "Cache signer service requires its two read-only views, Controller, and policy authority";
      }
      {
        assertion = cfg.credentials.seed != null && cfg.credentials.publicKey != null && cfg.credentials.memoryCeiling != null;
        message = "Cache signer service requires separate seed, public pin, and memory-ceiling credentials";
      }
      {
        assertion = cfg.credentials.publicKey == policy.credentials.cacheOwnerReadbackPublicKey;
        message = "Cache signer and root policy authority must load the same independently provisioned Cache public pin";
      }
      {
        assertion = controllerService.credentials.cacheOwnerReadbackSigningKey == null && controllerService.credentials.cacheOwnerReadbackPublicKey == null;
        message = "Controller diagnostic Cache signing must be disabled when the separate Cache-only signer is enabled";
      }
      {
        assertion = let
          service = config.systemd.services.aos-sandbox-cache-signerd.serviceConfig;
          inaccessible = service.InaccessiblePaths or [];
          strictSystem = (service.ProtectSystem or null) == "strict";
        in
          strictSystem
          && (service.CapabilityBoundingSet or null) == ""
          && (service.ReadWritePaths or []) == []
          && (service.BindPaths or []) == []
          && inaccessible == ["/run/aos/sandbox-policy-cache-journals"];
        message = "Cache signer needs original Cache-name metadata through searchable read-only parents, with no broad write path";
      }
    ];

    systemd.sockets.aos-sandbox-cache-signerd = {
      description = "AOS Cache-only signer root and Controller ingress";
      wantedBy = ["sockets.target"];
      requires = ["aos-sandbox-cache-signer-views.service"];
      after = ["aos-sandbox-cache-signer-views.service"];
      unitConfig.BindsTo = ["aos-sandbox-cache-signer-views.service"];
      socketConfig = {
        ListenStream = "/run/aos/sandbox-cache-signerd.sock";
        Service = "aos-sandbox-cache-signerd.service";
        Accept = false;
        SocketUser = "aos-cache-signer";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0660";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-cache-signerd = {
      description = "AOS separate Cache-only readback signer";
      requires = ["aos-sandbox-cache-signer-views.service" "aos-sandbox-cache-signerd.socket"];
      after = ["aos-sandbox-cache-signer-views.service" "aos-sandbox-cache-signerd.socket"];
      unitConfig.BindsTo = ["aos-sandbox-cache-signer-views.service"];
      serviceConfig = {
        Type = "simple";
        Sockets = ["aos-sandbox-cache-signerd.socket"];
        StandardInput = "socket";
        ExecStart = "${cfg.package}/bin/aos-sandbox-cache-signerd ${toString controller.uid} ${toString controller.gid} ${toString views.uid} ${toString views.gid}";
        LoadCredential =
          lib.optionals (cfg.credentials.seed != null) ["cache-signer-v2-seed:/run/credentials/@system/${cfg.credentials.seed}"]
          ++ lib.optionals (cfg.credentials.publicKey != null) ["cache-owner-readback-public-key:/run/credentials/@system/${cfg.credentials.publicKey}"]
          ++ lib.optionals (cfg.credentials.memoryCeiling != null) ["cache-signer-v2-memory-ceiling:/run/credentials/@system/${cfg.credentials.memoryCeiling}"];
        User = "aos-cache-signer";
        Group = "aos-cache-signer";
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
        # Exact-name and legacy checks stat the original Cache root names.
        # Their 0700 contents remain inaccessible outside the idmapped views.
        InaccessiblePaths = [
          "/run/aos/sandbox-policy-cache-journals"
        ];
      };
    };
  };
}
