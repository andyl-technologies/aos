##! modules/sandbox/policy-authority.nix — signed deployment policy input custody
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.policyAuthority;
  controller = config.aos.sandbox.controller;
  requiredCredentials = {
    deploymentPublicKey = "deployment-public-key";
    deploymentHeadPacket = "deployment-head.packet";
    nodePolicy = "node-policy.json";
    sitePolicy = "site-policy.json";
    backendCapabilities = "backend-capabilities.json";
    catalogs = "catalogs.json";
    projectPublicKey = "project-public-key";
  };
  projectCredentials = {
    projectHeadPacket = "project-head.packet";
    projectLayer = "project-layer.json";
    projectHeadPacketV2 = "project-head-v2.packet";
    projectLayerV2 = "project-layer-v2.json";
  };
  cacheCredentials = {
    cacheOwnerReadbackPublicKey = "cache-owner-readback-public-key";
  };
  credentialFiles = requiredCredentials // projectCredentials // cacheCredentials;
in {
  options.aos.sandbox.policyAuthority = {
    enable = lib.mkEnableOption "the root-owned signed deployment policy input authority";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "The package containing the independent policy authority executable.";
    };

    credentials = lib.mapAttrs (option: _:
      lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description =
          if option == "deploymentPublicKey"
          then "Externally provisioned 80-byte AOSPDK01 deployment signer pin (nonzero generation and public key). Raw 32-byte keys are rejected."
          else if option == "projectPublicKey"
          then "Externally provisioned 80-byte AOSPPK01 project signer pin (nonzero generation and public key). Raw 32-byte keys are rejected."
          else if option == "cacheOwnerReadbackPublicKey"
          then "Optional 80-byte AOSCPK01 Cache-only signer pin. Root persists exact replay but does not accept Cache readbacks or publish Create."
          else if option == "projectHeadPacketV2" || option == "projectLayerV2"
          then "Optional AOSPPH02/AOSPPL02 project source; both credentials are required for the closed AOSPHQ04 path."
          else "Externally provisioned signed deployment policy authority input.";
      })
    credentialFiles;
  };

  config = lib.mkIf cfg.enable {
    assertions = lib.mapAttrsToList (option: _: {
      assertion = cfg.credentials.${option} != null;
      message = "aos.sandbox.policyAuthority.credentials.${option} is required";
    })
    requiredCredentials
    ++ [
      {
        assertion =
          (cfg.credentials.projectHeadPacket == null)
          == (cfg.credentials.projectLayer == null);
        message = "aos.sandbox.policyAuthority V1 project packet and input credentials must be provisioned together";
      }
      {
        assertion =
          (cfg.credentials.projectHeadPacketV2 == null)
          == (cfg.credentials.projectLayerV2 == null);
        message = "aos.sandbox.policyAuthority V2 project packet and input credentials must be provisioned together";
      }
      {
        assertion =
          (cfg.credentials.projectHeadPacket != null)
          != (cfg.credentials.projectHeadPacketV2 != null);
        message = "aos.sandbox.policyAuthority requires exactly one project source version";
      }
    ];

    systemd.services.aos-sandbox-policy-authorityd = {
      description = "AOS signed deployment policy input authority";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-sandbox-policy-authorityd ${toString controller.uid} ${toString controller.gid}";
        LoadCredential =
          lib.mapAttrsToList (option: name: "${name}:/run/credentials/@system/${cfg.credentials.${option}}")
          (lib.filterAttrs (option: _: cfg.credentials.${option} != null) credentialFiles);
        StateDirectory = "aos/sandbox/policy-compiler";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-policy-authority";
        RuntimeDirectoryMode = "0710";
        User = "root";
        Group = "aos-sandboxd";
        UMask = "0007";

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
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
      };
    };
  };
}
