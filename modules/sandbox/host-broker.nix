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
    {
      name = "host-storage-broker";
      description = "Storage-facing Host broker";
      role = "broker";
      journalRoot = "/var/lib/aos/sandbox-host/broker-session/storage";
      options = {
        manifest = "brokerSessionStorageManifest";
        hello = "brokerSessionStorageHelloKey";
        record = "brokerSessionStorageOutcomeKey";
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
      phase0ProbeSigningSeed = "phase0-probe-signing-seed-v1";
      phase0ProbePublicKey = "phase0-probe-public-key-v1";
    };
  configuredCredentials =
    lib.filterAttrs (name: _: cfg.credentials.${name} != null) credentialFields;
  # Sources are names in the platform credential namespace, not paths or
  # values. PID 1 copies their runtime bytes into the service credential
  # directory, so evaluating and building the system never captures secrets in
  # a derivation or Nix store path.
  hostCredentials = lib.filterAttrs (name: _: name != "phase0ProbeSigningSeed") configuredCredentials;
  loadCredentials =
    lib.mapAttrsToList (
      name: _: "${credentialFields.${name}}:/run/credentials/@system/${cfg.credentials.${name}}"
    )
    hostCredentials;
  phase0ProbeActive = cfg.credentials.phase0ProbeSigningSeed != null && cfg.credentials.phase0ProbePublicKey != null;
  phase0ProbeCredentials =
    if phase0ProbeActive && cfg.credentials.phase0ProbeSigningSeed != null && cfg.credentials.phase0ProbePublicKey != null
    then [
      "phase0-probe-signing-seed-v1:/run/credentials/@system/${cfg.credentials.phase0ProbeSigningSeed}"
      "phase0-probe-public-key-v1:/run/credentials/@system/${cfg.credentials.phase0ProbePublicKey}"
    ]
    else [];
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
            else if name == "phase0ProbeSigningSeed"
            then "Dedicated external Ed25519 signing seed available only to the fixed shifted-target phase-0 inspector."
            else if name == "phase0ProbePublicKey"
            then "Independent external Ed25519 verifier pin for the boot-local shifted-target phase-0 report."
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
        {
          assertion =
            (cfg.credentials.phase0ProbeSigningSeed == null)
            == (cfg.credentials.phase0ProbePublicKey == null);
          message = "phase-0 probe signing seed and independent verifier pin must be provisioned together";
        }
        {
          assertion = cfg.credentials.backendReadiness == null || phase0ProbeActive;
          message = "phase-0 backend readiness requires the fixed shifted-target inspector credentials";
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

    # This listener has its own signed audience and custody root. Method 34 is
    # still excluded from the production profile until descriptor replay is live.
    systemd.sockets.aos-sandbox-host-storage = {
      description = "AOS Storage-facing sandbox Host broker socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-host/storage.sock";
        FileDescriptorName = "aos-sandbox-host-storage";
        Service = "aos-sandbox-hostd.service";
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandbox-hostd = {
      description = "AOS fixed-function sandbox host broker";
      requires = [
        "aos-sandbox-hostd.socket"
        "aos-sandbox-host-root-mount.socket"
        "aos-sandbox-host-storage.socket"
        "dbus.socket"
      ] ++ lib.optional phase0ProbeActive "aos-sandbox-host-phase0-inspector.service";
      after = [
        "aos-sandbox-hostd.socket"
        "aos-sandbox-host-root-mount.socket"
        "aos-sandbox-host-storage.socket"
        "dbus.socket"
        "local-fs.target"
      ] ++ lib.optional phase0ProbeActive "aos-sandbox-host-phase0-inspector.service";
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        Sockets = [
          "aos-sandbox-hostd.socket"
          "aos-sandbox-host-root-mount.socket"
          "aos-sandbox-host-storage.socket"
        ];
        ExecStartPre =
          ["${pkgs.coreutils}/bin/test -f ${pkgs.systemd}/share/aos/backend-policy-artifact-v2"]
          ++ brokerSessionConfiguration.installCommands;
        ExecStart = "${cfg.package}/bin/aos-sandbox-hostd ${toString controller.uid} ${toString controller.gid} ${pkgs.systemd}/bin/systemd-nspawn ${cfg.guardianPackage}/bin/aos-sandbox-guardian ${pkgs.aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
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

    systemd.services.aos-sandbox-host-phase0-target = lib.mkIf phase0ProbeActive {
      description = "AOS fixed shifted-userns phase-0 target";
      after = ["local-fs.target"];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/aos-sandbox-host-phase0-probe target";
        RuntimeMaxSec = "60s";
        TimeoutStopSec = "1s";
        Restart = "no";
        User = "root";
        Group = "root";
        CapabilityBoundingSet = "";
        PrivateUsers = "managed";
        RestrictNamespaces = true;
        PrivateNetwork = true;
        PrivateDevices = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        MemoryMax = "64M";
        TasksMax = 4;
      };
    };

    systemd.services.aos-sandbox-host-phase0-inspector = lib.mkIf phase0ProbeActive {
      description = "AOS fixed privileged shifted-userns phase-0 inspector";
      requires = ["aos-sandbox-host-phase0-target.service" "dbus.socket"];
      after = ["aos-sandbox-host-phase0-target.service" "dbus.socket" "local-fs.target"];
      before = ["aos-sandbox-hostd.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${cfg.package}/bin/aos-sandbox-host-phase0-probe inspect ${pkgs.systemd}/bin/systemd-nspawn ${cfg.package}/bin/aos-sandbox-hostd ${pkgs.aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
        LoadCredential = phase0ProbeCredentials;
        TimeoutStartSec = "20s";
        Restart = "no";
        User = "root";
        Group = "root";
        UMask = "0077";
        StateDirectory = "aos/sandbox-host-phase0";
        StateDirectoryMode = "0700";
        CapabilityBoundingSet = ["CAP_SYS_PTRACE"];
        AmbientCapabilities = ["CAP_SYS_PTRACE"];
        SecureBits = ["noroot" "noroot-locked" "no-setuid-fixup" "no-setuid-fixup-locked"];
        DevicePolicy = "closed";
        LimitNOFILE = 64;
        LimitCORE = 0;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        MemoryMax = "192M";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        SystemCallArchitectures = ["native"];
        SystemCallFilter = ["@system-service" "~@mount" "~@reboot" "~@swap" "~@module" "~@raw-io" "~bpf" "~setns" "~unshare"];
        SystemCallErrorNumber = "EPERM";
        TasksMax = 8;
      };
    };
  };
}
