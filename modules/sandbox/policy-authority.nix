##! modules/sandbox/policy-authority.nix — signed deployment policy input custody
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.policyAuthority;
  requiredCredentials = {
    deploymentPublicKey = "deployment-public-key";
    deploymentHeadPacket = "deployment-head.packet";
    nodePolicy = "node-policy.json";
    sitePolicy = "site-policy.json";
    backendCapabilities = "backend-capabilities.json";
    catalogs = "catalogs.json";
  };
in {
  options.aos.sandbox.policyAuthority = {
    enable = lib.mkEnableOption "the root-owned signed deployment policy input authority";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "The package containing the independent policy authority executable.";
    };

    credentials = lib.mapAttrs (_: _:
      lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "Externally provisioned signed deployment policy authority input.";
      })
    requiredCredentials;
  };

  config = lib.mkIf cfg.enable {
    assertions = lib.mapAttrsToList (option: _: {
      assertion = cfg.credentials.${option} != null;
      message = "aos.sandbox.policyAuthority.credentials.${option} is required";
    })
    requiredCredentials;

    systemd.services.aos-sandbox-policy-authorityd = {
      description = "AOS signed deployment policy input authority";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/aos-sandbox-policy-authorityd";
        LoadCredential = lib.mapAttrsToList (option: name:
          "${name}:/run/credentials/@system/${cfg.credentials.${option}}")
        (lib.filterAttrs (option: _: cfg.credentials.${option} != null) requiredCredentials);
        StateDirectory = "aos/sandbox/policy-compiler";
        StateDirectoryMode = "0700";
        UMask = "0077";

        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = [];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
      };
    };
  };
}
