##! modules/sandbox/host-broker.nix — fixed root runtime broker boundary
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.hostBroker;
  controller = config.aos.sandbox.controller;
  canonicalReadback = pkgs.aosSelinuxKernelPolicyReadbackForKernel config.system.build.kernel;
  canonicalReadbackPath = "${canonicalReadback}/policy.33";

  # One image-owned profile drives both PID 1's unit and Host's exact readback.
  hostSyscallProfile = builtins.fromJSON (builtins.readFile ../../crates/aos-sandbox-host/src/plan/host_syscall_profile_v1.json);
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
      runtimeBootstrapTrustPin = "runtime-bootstrap-trust-pin-v1";
      opensshAttachHostPrivateKey = "openssh-attach-host-private-key-v1";
      phase0ProbeSigningSeed = "phase0-probe-signing-seed-v1";
      phase0ProbePublicKey = "phase0-probe-public-key-v1";
      canaryApprovalPublicKey = "host-canary-approval-public-key-v1";
      canaryJob = "host-canary-job-v1";
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
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  selectedHost = config.systemd.services.aos-sandbox-hostd;
  pid1Image = "${config.systemd.package}/lib/systemd/systemd";
  hostImage = "${cfg.package}/bin/aos-sandbox-hostd";
  canaryArgv = [
    hostImage
    (toString controller.uid)
    (toString controller.gid)
    "${pkgs.systemd}/bin/systemd-nspawn"
    "${cfg.guardianPackage}/bin/aos-sandbox-guardian"
    canonicalReadbackPath
    "--host-canary-v1"
  ];
  canaryOpenFiles = [
    "${pid1Image}:aos-host-pid1-image:read-only"
    "${canaryProfile}/profile.json:aos-host-startup-profile:read-only"
  ];

  # Render the same final merged service, substituting only the profile's
  # complete OpenFile line. Removing that one self-reference avoids a unit /
  # profile store-path cycle; no other command, property or byte is exempted.
  normalizedHost = selectedHost // {
    environment = config.systemd.globalEnvironment // selectedHost.environment;
    serviceConfig = selectedHost.serviceConfig // {
      OpenFile = [
        "${pid1Image}:aos-host-pid1-image:read-only"
        "@AOS_HOST_CANARY_PROFILE@:aos-host-startup-profile:read-only"
      ];
    };
  };
  renderedHost = systemdLib.serviceToUnit normalizedHost;
  materializedHost = builtins.replaceStrings
    (builtins.map (job: job.placeholder) renderedHost.jobScripts)
    (builtins.map (job: job.path) renderedHost.jobScripts)
    renderedHost.text;
  canaryProfile = pkgs.runCommand "aos-host-canary-startup-profile" {
    nativeBuildInputs = [pkgs.python3 pkgs.coreutils];
    unitContract = materializedHost;
    passAsFile = ["unitContract"];
    argvContract = builtins.toJSON canaryArgv;
    preContract = builtins.toJSON (selectedHost.serviceConfig.ExecStartPre or []);
    postContract = builtins.toJSON (selectedHost.serviceConfig.ExecStartPost or []);
    parentResourcesContract = builtins.toJSON cfg.nodeParentResources;
    hostServiceLimitsContract = builtins.toJSON cfg.canaryHostServiceLimits;
    guardianServiceLimitsContract = builtins.toJSON cfg.canaryGuardianServiceLimits;
  } ''
    set -eu
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 -B - "$out/profile.json" \
      "$unitContractPath" ${pid1Image} ${hostImage} ${canonicalReadbackPath} \
      ${pkgs.systemd}/share/aos/payload-filter-programs-v1 <<'PY'
    import hashlib
    import json
    import os
    import shlex
    import sys
    from pathlib import Path

    output, unit_path, pid1, host, policy, programs = map(Path, sys.argv[1:])
    unit = unit_path.read_bytes()
    marker = b"OpenFile=@AOS_HOST_CANARY_PROFILE@:aos-host-startup-profile:read-only\n"
    if not unit or len(unit) > 65536 or unit.splitlines(keepends=True).count(marker) != 1:
        raise ValueError("Host canary unit must contain exactly its complete profile line")
    argv = json.loads(os.environ["argvContract"])
    expected = ("ExecStart=" + " ".join(argv) + "\n").encode()
    commands = [line for line in unit.splitlines(keepends=True) if line.startswith(b"ExecStart=")]
    if commands != [expected]:
        raise ValueError("Host canary unit command differs from its fixed installed caller")

    def digest(path):
        return list(hashlib.sha256(path.read_bytes()).digest())

    # These are only the existing generated command DATA. PID1 supplies its
    # actual parsed command arrays independently during startup admission.
    pre = [shlex.split(command) for command in json.loads(os.environ["preContract"])]
    post = [shlex.split(command) for command in json.loads(os.environ["postContract"])]
    profile = {
        "version": 2,
        "pid1_path": str(pid1),
        "pid1_sha256": digest(pid1),
        "host_path": str(host),
        "host_sha256": digest(host),
        "argv": argv,
        "exec_start_pre": pre,
        "exec_start_post": post,
        "unit_sha256": list(hashlib.sha256(unit).digest()),
        "policy_path": str(policy),
        "policy_sha256": digest(policy),
        "payload_programs_path": str(programs),
        "payload_programs_sha256": digest(programs),
        "parent_resources": json.loads(os.environ["parentResourcesContract"]),
        "cpu_period_usec": 100000,
        "host_service_limits": json.loads(os.environ["hostServiceLimitsContract"]),
        "guardian_service_limits": json.loads(os.environ["guardianServiceLimitsContract"]),
    }
    encoded = json.dumps(profile, separators=(",", ":")).encode()
    if len(encoded) > 1048576:
        raise ValueError("Host canary profile exceeds its fixed admission bound")
    output.write_bytes(encoded)
    PY
    chmod 0444 "$out/profile.json"
  '';
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

    canary = lib.mkEnableOption
      "the independently approved private startup canary, not public runtime activation";

    nodeParentResources = lib.mkOption {
      type = lib.types.listOf (lib.types.addCheck lib.types.int
        (value: value >= 0 && value <= 9223372036854775807));
      default = [];
      description = ''
        Independently administered finite readiness-canary pool in the exact
        ResourceDimension::ALL order. The 22 values are not derived from a job
        and do not establish full-project accounting or physical reservation.
      '';
    };

    canaryHostServiceLimits = lib.mkOption {
      type = lib.types.listOf (lib.types.addCheck lib.types.int
        (value: value > 0 && value <= 9223372036854775807));
      default = [];
      description = ''
        Host CPU microseconds per 100ms, memory bytes, tasks and file descriptors.
        Each independently configured value must fit its parent pool dimension;
        these Host limits do not enforce the separate Guardian or payload unit.
      '';
    };

    canaryGuardianServiceLimits = lib.mkOption {
      type = lib.types.listOf (lib.types.addCheck lib.types.int
        (value: value > 0 && value <= 9223372036854775807));
      default = [];
      description = ''
        Independently selected Guardian CPU microseconds per 100ms, memory
        bytes, tasks and file descriptors. These sibling limits do not replace
        the signed workload limits or prove complete resource funding.
      '';
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
            else if name == "runtimeBootstrapTrustPin"
            then "Optional externally provisioned AOSRBT01 signer pin and monotonic deployment-epoch floor loaded as ${credentialFile}; the dormant proof decoder alone grants no Host bootstrap authority."
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
          assertion = pkgs.systemd.version == hostSyscallProfile.systemdVersion;
          message = "Host seccomp profile requires systemd ${hostSyscallProfile.systemdVersion}";
        }
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
        {
          assertion = !cfg.canary || (phase0ProbeActive
            && cfg.credentials.canaryApprovalPublicKey != null
            && cfg.credentials.canaryJob != null
            && cfg.credentials.guestAgentSigningSeed != null
            && cfg.credentials.opensshAttachHostPrivateKey != null
            && cfg.credentials.opensshAttachTrust != null
            && cfg.credentials.opensshAttachGrantPublicKey != null);
          message = "Host canary requires independent original job/key, phase-0 and Guest attach inputs";
        }
        {
          assertion = !cfg.canary || (builtins.length cfg.nodeParentResources == 22
            && builtins.length cfg.canaryHostServiceLimits == 4
            && lib.all (index:
              builtins.elemAt cfg.canaryHostServiceLimits index
              <= builtins.elemAt cfg.nodeParentResources index) [0 1 2 3]
            && builtins.div (builtins.elemAt cfg.canaryHostServiceLimits 0) 1000 * 1000
              == builtins.elemAt cfg.canaryHostServiceLimits 0
            && builtins.elemAt cfg.canaryHostServiceLimits 0 <= 922337203685477580
            && builtins.div (builtins.elemAt cfg.canaryHostServiceLimits 1) 4096 * 4096
              == builtins.elemAt cfg.canaryHostServiceLimits 1);
          message = "Host canary requires an independent finite 22-resource pool and matching aligned Host limits";
        }
        {
          assertion = !cfg.canary || (builtins.length cfg.nodeParentResources == 22
            && builtins.length cfg.canaryGuardianServiceLimits == 4
            && lib.all (index:
              builtins.elemAt cfg.canaryGuardianServiceLimits index
              <= builtins.elemAt cfg.nodeParentResources index) [0 1 2 3]
            && builtins.div (builtins.elemAt cfg.canaryGuardianServiceLimits 0) 1000 * 1000
              == builtins.elemAt cfg.canaryGuardianServiceLimits 0
            && builtins.elemAt cfg.canaryGuardianServiceLimits 0 <= 922337203685477580
            && builtins.div (builtins.elemAt cfg.canaryGuardianServiceLimits 1) 4096 * 4096
              == builtins.elemAt cfg.canaryGuardianServiceLimits 1);
          message = "Host canary requires independently configured finite sibling Guardian limits";
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
      ];
      after =
        [
          "aos-sandbox-hostd.socket"
          "aos-sandbox-host-root-mount.socket"
          "aos-sandbox-host-storage.socket"
          "dbus.socket"
          "local-fs.target"
        ]
        ++ lib.optional phase0ProbeActive "aos-sandbox-host-phase0-inspector.service";
      unitConfig = {
        # An exited probe cannot remain authoritative after its target dies.
        BindsTo = lib.optional phase0ProbeActive "aos-sandbox-host-phase0-inspector.service";
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
        ExecStart = "${cfg.package}/bin/aos-sandbox-hostd ${toString controller.uid} ${toString controller.gid} ${pkgs.systemd}/bin/systemd-nspawn ${cfg.guardianPackage}/bin/aos-sandbox-guardian ${canonicalReadbackPath}"
          + lib.optionalString cfg.canary " --host-canary-v1";
        # This public digest is pinned to the deployed immutable guest package,
        # independent of Storage's assignment-bound physical root proof.
        LoadCredential =
          loadCredentials
          ++ brokerSessionConfiguration.loadCredentials
          ++ ["guest-root-package-binding-v1:${pkgs.aos-sandbox-guest-root-template}/package-binding"];
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory =
          if cfg.canary
          then ["aos/sandbox-host" "aos/sandbox-host/canary-capacity-v1"]
          else "aos/sandbox-host";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-host";
        RuntimeDirectoryMode = "0710";
        UMask = "0077";

        # hostd probes the fixed shifted target under this exact service
        # sandbox. That does not prove access to a real nspawn payload; do not
        # add CAP_SYS_PTRACE to make such access appear to work.
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
        SystemCallArchitectures = hostSyscallProfile.architectures;
        SystemCallFilter = hostSyscallProfile.filter;
        SystemCallErrorNumber = hostSyscallProfile.errorNumber;
      } // lib.optionalAttrs cfg.canary {
        OpenFile = canaryOpenFiles;
        SELinuxContext = "system_u:system_r:aos_sandbox_host_t";
        ExtraFileDescriptorNames = [];
        FileDescriptorStoreMax = 0;
        CPUQuota = "${toString (builtins.div (builtins.elemAt cfg.canaryHostServiceLimits 0) 1000)}%";
        CPUQuotaPeriodSec = "100ms";
        MemoryMax = builtins.elemAt cfg.canaryHostServiceLimits 1;
        TasksMax = builtins.elemAt cfg.canaryHostServiceLimits 2;
        LimitNOFILE = "${toString (builtins.elemAt cfg.canaryHostServiceLimits 3)}:${toString (builtins.elemAt cfg.canaryHostServiceLimits 3)}";
      };
    };

    systemd.services.aos-sandbox-host-phase0-target = lib.mkIf phase0ProbeActive {
      description = "AOS fixed shifted-userns phase-0 target";
      after = ["local-fs.target"];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${cfg.package}/bin/aos-sandbox-host-phase0-probe target";
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
      requires = ["dbus.socket"];
      after = ["aos-sandbox-host-phase0-target.service" "dbus.socket" "local-fs.target"];
      before = ["aos-sandbox-hostd.service"];
      unitConfig.BindsTo = ["aos-sandbox-host-phase0-target.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${cfg.package}/bin/aos-sandbox-host-phase0-probe inspect ${pkgs.systemd}/bin/systemd-nspawn ${cfg.package}/bin/aos-sandbox-hostd ${canonicalReadbackPath}";
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
