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
    projectHeadPacket = "project-head.packet";
    projectLayer = "project-layer.json";
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
        description =
          if option == "deploymentPublicKey" then
            "Externally provisioned 80-byte AOSPDK01 deployment signer pin (nonzero generation and public key). Raw 32-byte keys are rejected."
          else if option == "projectPublicKey" then
            "Externally provisioned 80-byte AOSPPK01 project signer pin (nonzero generation and public key). Raw 32-byte keys are rejected."
          else
            "Externally provisioned signed deployment policy authority input.";
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
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-sandbox-policy-authorityd ${toString controller.uid} ${toString controller.gid}";
        LoadCredential = lib.mapAttrsToList (option: name:
          "${name}:/run/credentials/@system/${cfg.credentials.${option}}")
        (lib.filterAttrs (option: _: cfg.credentials.${option} != null) requiredCredentials);
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
