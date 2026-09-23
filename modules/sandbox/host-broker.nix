##! modules/sandbox/host-broker.nix — fixed root runtime broker boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.hostBroker;
  controller = config.aos.sandbox.controller;
  brokerSession = import ./_broker-session-credentials.nix {inherit lib pkgs;};
  brokerSessionEndpoints = [
    {
      name = "host-broker";
      description = "controller-facing Host broker";
      role = "broker";
      journalRoot = "/var/lib/aos/sandbox-host/broker-session/controller";
      options = {
        manifest = "brokerSessionManifest";
        hello = "brokerSessionHelloKey";
        record = "brokerSessionOutcomeKey";
      };
    }
    {
      name = "host-root-mount-broker";
      description = "RootMount-facing Host broker";
      role = "broker";
      journalRoot = "/var/lib/aos/sandbox-host/broker-session/root-mount";
      options = {
        manifest = "brokerSessionRootMountManifest";
        hello = "brokerSessionRootMountHelloKey";
        record = "brokerSessionRootMountOutcomeKey";
      };
    }
  ];
  brokerSessionConfiguration = brokerSession.configure cfg.credentials brokerSessionEndpoints;
  authorityCredentialFields = {
    brokerPlanPolicy = "broker-plan-policy.cbor";
    brokerPlanPublicKey = "broker-plan-public-key";
    brokerRevocationScope = "broker-revocation-scope";
    ownershipLeasePolicy = "ownership-lease-policy.cbor";
    ownershipLeasePublicKey = "ownership-lease-public-key";
    nodeId = "node-id";
    journalMacKey = "journal-mac-key";
  };
  credentialFields =
    authorityCredentialFields
    // {
      backendReadiness = "backend-readiness.json";
      opensshAttachTrust = "openssh-attach-trust.json";
      opensshAttachGrantPublicKey = "openssh-attach-grant-public-key";
      guestAgentSigningSeed = "guest-agent-signing-seed-v1";
      opensshAttachHostPrivateKey = "openssh-attach-host-private-key-v1";
    };
  configuredCredentials =
    lib.filterAttrs (name: _: cfg.credentials.${name} != null) credentialFields;
  # Sources are names in the platform credential namespace, not paths or
  # values. PID 1 copies their runtime bytes into the service credential
  # directory, so evaluating and building the system never captures secrets in
  # a derivation or Nix store path.
  loadCredentials =
    lib.mapAttrsToList (
      name: _: "${credentialFields.${name}}:/run/credentials/@system/${cfg.credentials.${name}}"
    )
    configuredCredentials;
in {
  options.aos.sandbox.hostBroker = {
    enable = lib.mkEnableOption "the fixed AOS sandbox host broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandbox-hostd;
      defaultText = "pkgs.aos-sandbox-hostd";
      description = "The independently packaged host broker executable.";
    };

    guardianPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandbox-guardian;
      defaultText = "pkgs.aos-sandbox-guardian";
      description = "The descriptor-pinned per-assignment Guardian executable.";
    };

    controllerUid = lib.mkOption {
      type = lib.types.int;
      default = 811;
      description = "Compatibility default for aos.sandbox.controller.uid.";
    };

    controllerGid = lib.mkOption {
      type = lib.types.int;
      default = 811;
      description = "Compatibility default for aos.sandbox.controller.gid.";
    };

    credentials =
      lib.mapAttrs (name: credentialFile:
        lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description =
            if name == "backendReadiness"
            then "Optional protected boot-local readiness claims published externally as ${credentialFile}; ingestion alone never enables Apply."
            else if name == "opensshAttachTrust"
            then "Optional externally provisioned OpenSSH attach trust pins (endpoint, account, server host public key, and user CA public key) loaded as ${credentialFile}; the per-operation gate configuration digest is signed in the pending grant."
            else if name == "opensshAttachGrantPublicKey"
            then "Optional dedicated controller OpenSSH attach-grant verifier key loaded as ${credentialFile}; broker-plan verification keys cannot authorize attach grants."
            else if name == "guestAgentSigningSeed"
            then "Optional externally provisioned AOSGSK01 guest-agent signing seed loaded as ${credentialFile}; its derived public key must match the protected runtime peer before launch."
            else if name == "opensshAttachHostPrivateKey"
            then "Optional externally provisioned unencrypted Ed25519 OpenSSH server private key loaded as ${credentialFile}; its public key must match independent protected attach trust pins before launch."
            else "External system credential loaded as ${credentialFile}; its bytes never enter the Nix store.";
        })
      credentialFields
      // brokerSession.mkOptions brokerSessionEndpoints;
  };

  config = lib.mkIf cfg.enable {
    assertions =
      lib.mapAttrsToList (name: credentialFile: {
        assertion = cfg.credentials.${name} != null;
        message = "aos.sandbox.hostBroker.credentials.${name} is required for ${credentialFile}";
      })
      authorityCredentialFields
      ++ brokerSessionConfiguration.assertions
      ++ [
        {
          assertion =
            (cfg.credentials.opensshAttachTrust == null)
            == (cfg.credentials.opensshAttachGrantPublicKey == null);
          message = "OpenSSH attach trust and dedicated attach-grant verifier credentials must be provisioned together";
        }
      ];

    systemd.sockets.aos-sandbox-hostd = {
      description = "AOS controller-facing sandbox Host broker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-host/control.sock";
        FileDescriptorName = "aos-sandbox-host";
        Service = "aos-sandbox-hostd.service";
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.sockets.aos-sandbox-host-root-mount = {
      description = "AOS RootMount-facing sandbox Host broker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-host/root-mount.sock";
        FileDescriptorName = "aos-sandbox-host-root-mount";
        Service = "aos-sandbox-hostd.service";
        PassCredentials = true;
        PassPIDFD = true;
        # RootMount has no DAC-override capability. The authenticated session
        # still pins its exact RootMount audience and protected credentials.
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0660";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-hostd = {
      description = "AOS fixed-function sandbox host broker";
      requires = [
        "aos-sandbox-hostd.socket"
        "aos-sandbox-host-root-mount.socket"
        "dbus.socket"
      ];
      after = [
        "aos-sandbox-hostd.socket"
        "aos-sandbox-host-root-mount.socket"
        "dbus.socket"
        "local-fs.target"
      ];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        ExecStartPre =
          ["${pkgs.coreutils}/bin/test -f ${pkgs.systemd}/share/aos/backend-policy-artifact-v1"]
          ++ brokerSessionConfiguration.installCommands;
        ExecStart = "${cfg.package}/bin/aos-sandbox-hostd ${toString controller.uid} ${toString controller.gid} ${pkgs.systemd}/bin/systemd-nspawn ${cfg.guardianPackage}/bin/aos-sandbox-guardian";
        # This public digest is pinned to the deployed immutable guest package,
        # independent of Storage's assignment-bound physical root proof.
        LoadCredential =
          loadCredentials
          ++ brokerSessionConfiguration.loadCredentials
          ++ ["guest-root-package-binding-v1:${pkgs.aos-sandbox-guest-root-template}/package-binding"];
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/sandbox-host";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-host";
        RuntimeDirectoryMode = "0710";
        UMask = "0077";

        # hostd probes the pidfs namespace ioctls against itself under this
        # exact service sandbox. Do not grant CAP_SYS_PTRACE merely to cross
        # the distinct ptrace check for a user-namespace-shifted payload;
        # launch remains gated until that narrow access is proven separately.
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
