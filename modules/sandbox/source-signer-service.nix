##! modules/sandbox/source-signer-service.nix — separate Source-only hold signer
{
  config,
  lib,
  pkgs,
  ...
}: let
  identitySocketOrdering = import ./_identity-socket-ordering.nix {inherit config lib;};
  credentialNameType = import ./_credential-name-type.nix {inherit lib;};

  cfg = config.aos.sandbox.sourceSignerService;
  controller = config.aos.sandbox.controller;
  selectedPackage = import ./_selected-controller-package.nix {inherit config pkgs;};
  view = config.aos.sandbox.sourceSignerView;
  policy = config.aos.sandbox.policyAuthority;
  signerServiceHardening = import ./_signer-service-hardening.nix;
  protectedOrigin = config.aos.sandbox.resourceBank.parentEnclosure != null;
  expectedExecStart = "${cfg.package}/bin/aos-sandbox-source-signerd ${toString controller.uid} ${toString controller.gid} ${toString view.uid} ${toString view.gid}";
  sourceService = config.systemd.services.aos-sandbox-source-signerd;
  sourceConfig = sourceService.serviceConfig;
  sourceSocket = config.systemd.sockets.aos-sandbox-source-signerd.socketConfig;
  rootProfileFiles =
    lib.optional (policy._normalStartupProfile != null)
    "${policy._normalStartupProfile}/profile.json:aos-source-root-profile:read-only";
  profileMatches = import ./_fixed-signer-profile.nix;
in {
  options.aos.sandbox.sourceSignerService = {
    enable = lib.mkEnableOption "the separate, nonauthorizing Source-only hold signer";

    package = lib.mkOption {
      type = lib.types.package;
      default = selectedPackage;
      defaultText = "image-selected shared Controller artifact";
      description = "The package containing aos-sandbox-source-signerd.";
    };

    credentials = {
      seed = lib.mkOption {
        type = lib.types.nullOr credentialNameType;
        default = null;
        description = "Signer-private 32-byte Ed25519 Source-purpose seed.";
      };

      publicKey = lib.mkOption {
        type = lib.types.nullOr credentialNameType;
        default = null;
        description = "80-byte AOSSPK01 pin shared by name with the independently provisioned Root credential.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # The installed binary has one immediate selected cutover. Missing
        # original F/PID1 descriptors cannot select the ordinary library API.
        assertion =
          protectedOrigin
          && config.aos.sandbox.resourceBank.parentEnclosure.sourceSignerReceiving != null
          && config.aos.sandbox.resourceBank.parentEnclosure.sourceSignerSender != null;
        message = "installed Source signer requires its genuine Parent and explicit Source receiving/sender F/M slices";
      }
      {
        assertion =
          policy._normalStartupProfile
          != null
          && (sourceConfig.OpenFile or []) == rootProfileFiles
          && builtins.all (name: (sourceSocket.${name} or false) == true)
          ["PassCredentials" "PassPIDFD" "PassSecurity" "PassSubjectBeforeListen"];
        message = "installed Source signer requires its exact image-delivered Root profile and all three PID1 pre-listen subject options";
      }
      {
        assertion = !(config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0") || cfg.package == selectedPackage;
        message = "confined Source signer requires the exact evaluated policy-labelled AOS executable";
      }
      {
        # Parent03 selects a new finite machine-role launch profile. Ordinary
        # library callers and systemd's generic PAM/EnvFile support are separate.
        assertion =
          !protectedOrigin
          || (
            profileMatches {
              inherit config lib pkgs;
              package = cfg.package;
              unit = sourceService;
              identity = "aos-source-signer";
              expectedExec = expectedExecStart;
            }
          );
        message = "protected Source origin v1 requires the immutable policy-labelled image and its exact single signer role, no auxiliary commands, PAM or EnvironmentFile; no helper user/PID/BPF/delegated namespaces or DynamicUser, and the exact source-built systemd loader profile; generic systemd modes keep their existing features";
      }
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

    systemd.sockets.aos-sandbox-source-signerd = identitySocketOrdering.apply {
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
        PassSubjectBeforeListen = true;
        PassCredentials = true;
        PassPIDFD = true;
        PassSecurity = true;
      };
    };

    systemd.services.aos-sandbox-source-signerd = {
      description = "AOS separate Source-only hold signer";
      requires = ["aos-sandbox-source-signer-view.service" "aos-sandbox-source-signerd.socket"];
      after = ["aos-sandbox-source-signer-view.service" "aos-sandbox-source-signerd.socket"];
      unitConfig.BindsTo = ["aos-sandbox-source-signer-view.service"];
      serviceConfig =
        signerServiceHardening
        // {
          SELinuxContext = lib.mkIf (config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0") "system_u:system_r:aos_sandbox_source_signer_t";
          ProcSubset = "all";
          PrivateUsers = lib.mkIf protectedOrigin false;
          PrivatePIDs = lib.mkIf protectedOrigin false;
          PrivateBPF = lib.mkIf protectedOrigin false;
          DynamicUser = lib.mkIf protectedOrigin false;
          Type = "simple";
          Sockets = ["aos-sandbox-source-signerd.socket"];
          StandardInput = "socket";
          OpenFile = rootProfileFiles;
          ExecStart = expectedExecStart;
          LoadCredential =
            lib.optionals (cfg.credentials.seed != null) ["source-hold-signing-seed:/run/credentials/@system/${cfg.credentials.seed}"]
            ++ lib.optionals (cfg.credentials.publicKey != null) ["source-hold-public-key:/run/credentials/@system/${cfg.credentials.publicKey}"];
          User = "aos-source-signer";
          Group = "aos-source-signer";
          UMask = "0077";
        };
    };
  };
}
