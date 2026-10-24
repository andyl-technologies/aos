##! Disabled fixed Host055 association producer, not runtime/Create activation.
{
  config,
  lib,
  pkgs,
  ...
}: let
  credentialNameType = import ./_credential-name-type.nix {inherit lib;};

  cfg = config.aos.sandbox.runtimeDeploymentPublisher;
  storage = config.aos.sandbox.storageBroker;
  host = config.aos.sandbox.hostBroker;
  parent = config.aos.sandbox.resourceBank.parentEnclosure;
  normal = cfg.enable && cfg.bootPreparation;
  bootReceiving =
    if parent == null || parent.hostBootPreparationReceiving == null
    then {}
    else parent.hostBootPreparationReceiving;
  bootLimits =
    map (dimension: bootReceiving.${dimension} or 0)
    config.aos.sandbox.resourceBank._dimensionOrder;
  readinessDirectory = "/var/lib/aos/sandbox/runtime-deployment/readiness";
  controller = config.aos.sandbox.controller;
  selinux = config.aos.security.selinux;
  systemdLib = import ../../pkgs/system/_systemd-abilities/platform/render.nix {inherit lib pkgs;};
  publicRoles = [
    "runtime-deployment-genesis-v1"
    "runtime-deployment-provisioner-pin-v1"
    (
      if cfg.bootPreparation
      then "runtime-deployment-boot-purpose-v1"
      else "runtime-deployment-canary-purpose-v2"
    )
  ];
  publicDelivery = map (role: "${role}:/run/credentials/@system/${role}") publicRoles;
  independentCredentialSources =
    publicRoles
    ++ lib.optionals normal [
      host.credentials.phase0ProbePublicKey
      host.credentials.phase0ProbeSigningSeed
    ];
  publisher = pkgs.callPackage ../../pkgs/tools/aos-sandbox-runtime-publisher.nix {
    systemd = config.aos.manager.selected.package;
    kernelCloneLayout = config.system.build.kernel.dev;
    bootPreparation = cfg.bootPreparation;
  };
  helper = pkgs.aos-runtime-deployment-tpm-helper;
  storageArguments = [
    "${storage.package}/bin/aos-storaged"
    (toString controller.uid)
    (toString controller.gid)
    (toString storage.identityPoolStart)
    (toString storage.identityPoolSize)
    "${storage.zfsPackage}/sbin/zfs"
    storage.authorityDirectory
    storage.bootstrapDirectory
    "-"
    (toString storage.guestRootTemplate)
    (
      if storage.zfsHoldSigningKey == null
      then "-"
      else "zfs-hold-key-v1"
    )
    (
      if storage.executionOutputKey == null
      then "-"
      else storage.executionOutputKey
    )
  ];
  render = unit: let
    rendered = systemdLib.serviceToUnit (unit
      // {
        environment = config.systemd.globalEnvironment // unit.environment;
      });
  in
    builtins.replaceStrings
    (map (job: job.placeholder) rendered.jobScripts)
    (map (job: job.path) rendered.jobScripts)
    rendered.text;
  publisherUnit = config.systemd.services.aos-sandbox-runtime-publisher;
  normalizedPublisher =
    publisherUnit
    // {
      serviceConfig =
        publisherUnit.serviceConfig
        // {
          OpenFile = [
            "/proc/1/exe:aos-runtime-deployment-pid1-image:read-only"
            "@AOS_RUNTIME_DEPLOYMENT_PROFILE@:aos-runtime-deployment-startup-profile:read-only"
          ];
        };
    };
  profiles = import ../../lib/runtime-deployment-startup-profile.nix {
    inherit pkgs publisher helper storageArguments;
    bootPreparation = cfg.bootPreparation;
    hostd = host.package;
    storage = storage.package;
    systemd = config.aos.manager.selected.package;
    policy = selinux._productionPolicy;
    canonicalPolicy = selinux._canonicalReadback;
    publisherUnit = render normalizedPublisher;
    storageUnit = render config.systemd.services.aos-storaged;
  };
  externalCredential = description:
    lib.mkOption {
      type = lib.types.nullOr credentialNameType;
      default = null;
      inherit description;
    };
in {
  options.aos.sandbox.runtimeDeploymentPublisher = {
    enable = lib.mkEnableOption "the fixed Host055 association producer over an independently provisioned deployment";
    bootPreparation = lib.mkEnableOption "the genuine normal Source-funded boot preparation purpose over the same independently provisioned055 pair";
    signingSeed = externalCredential "Independent root-only nonzero32 publisher seed, never generated or put in the Nix store.";
    indexAuth = externalCredential "Distinct external055 index-only auth32; no hierarchy, define, clear or bootstrap authority.";
    _profile = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default =
        if cfg.enable
        then profiles.publisher
        else null;
      readOnly = true;
      internal = true;
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          (
            if normal
            then
              host.enable
              && host.componentControl
              && host.executionReceiving != null
              && host.credentials.backendReadiness == null
              && host.credentials.phase0ProbeSigningSeed != null
              && host.credentials.phase0ProbePublicKey != null
              && parent != null
              && parent.hostBootPreparationReceiving != null
              && parent.hostBootPreparationSender != null
            else
              storage.enable
              && storage.sourceOriginalWorkerStartup.enable
              && storage.package == pkgs.aos-storaged
              && storage.resolverPolicyDirectory == null
              && storage.credentials.gitCoverageEnrollment == null
          )
          && (import ./_fixed-systemd-profile.nix {inherit config pkgs;})
          && selinux.enable
          && selinux.bootMode == "immutable-stage0"
          && selinux.mode == "enforcing"
          && selinux.policy == "aos"
          && cfg.signingSeed != null
          && cfg.indexAuth != null
          && cfg.signingSeed != cfg.indexAuth
          && !(builtins.elem cfg.signingSeed independentCredentialSources)
          && !(builtins.elem cfg.indexAuth independentCredentialSources);
        message = "Host055 requires its selected original Source or Storage startup, independent genesis/provisioner/purpose delivery and provisioned055 main, sidecar and NV state";
      }
    ];

    # Fixed public delivery supplements rather than replaces the ordinary
    # Storage credentials/argv. The scalar only requests fail-closed admission.
    systemd.services.aos-storaged = lib.mkIf (!normal) {
      environment.AOS_RUNTIME_CANARY_DELIVERY_V2 = "1";
      serviceConfig = {
        LoadCredential = publicDelivery;
        # Selected startup authenticates an already healthy protected BSA
        # deployment. It cannot run the ordinary copy/chmod installer first.
        # Disabled configuration leaves that older installer list untouched.
        ExecStartPre = lib.mkForce [];
      };
    };
    environment.etc."aos/runtime-deployment-tpm-floor/mode".text = "required-v1\n";

    systemd.sockets.aos-sandbox-runtime-publisher = {
      description =
        if normal
        then "Original Source-funded BootPreparation listener"
        else "Fixed protected Storage-to-Host055 association listener";
      wantedBy = ["sockets.target"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig =
        {
          ListenSequentialPacket = "/run/aos/sandbox/runtime-deployment.sock";
          FileDescriptorName = "aos-runtime-deployment";
          Service = "aos-sandbox-runtime-publisher.service";
          Accept = false;
          PassCredentials = true;
          PassPIDFD = true;
          SocketUser = "root";
          SocketGroup = "root";
          SocketMode = "0600";
          DirectoryMode = "0700";
          RemoveOnStop = true;
        }
        // lib.optionalAttrs normal {
          PassSubjectBeforeListen = true;
          PassSecurity = false;
        };
    };
    systemd.services.aos-sandbox-runtime-publisher = {
      description =
        if normal
        then "One genuine normal BootPreparation over the original055 owners"
        else "One genuine canary association attempt over the original055 owners";
      requires =
        ["aos-sandbox-runtime-publisher.socket" "dbus.service"]
        ++ lib.optional normal "aos-sandbox-host-phase0-inspector.service";
      after =
        ["aos-sandbox-runtime-publisher.socket" "dbus.service"]
        ++ lib.optional normal "aos-sandbox-host-phase0-inspector.service";
      unitConfig.RequiresMountsFor = ["/sys/fs/cgroup" "/var/lib/aos/sandbox/runtime-deployment"];
      serviceConfig =
        {
          Type =
            if normal
            then "oneshot"
            else "exec";
          ExecStart = "${publisher}/bin/aos-sandbox-runtime-publisher ${
            if normal
            then "--boot-preparation-v1"
            else "--canary-association-v2"
          }";
          Sockets = ["aos-sandbox-runtime-publisher.socket"];
          OpenFile = [
            "/proc/1/exe:aos-runtime-deployment-pid1-image:read-only"
            "${cfg._profile}/profile.json:aos-runtime-deployment-startup-profile:read-only"
          ];
          LoadCredential =
            publicDelivery
            ++ [
              "runtime-deployment-signing-seed-v1:/run/credentials/@system/${cfg.signingSeed}"
              "runtime-deployment-tpm-index-auth-v1:/run/credentials/@system/${cfg.indexAuth}"
            ]
            ++ lib.optional normal
            "phase0-probe-public-key-v1:/run/credentials/@system/${host.credentials.phase0ProbePublicKey}";
          ExtraFileDescriptorNames = [];
          FileDescriptorStoreMax = 0;
          User = "root";
          Group = "root";
          SupplementaryGroups = "";
          Slice = "aos-control.slice";
          SELinuxContext = "system_u:system_r:aos_runtime_deployment_publisher_t";
          UMask = "0077";
          Restart = "no";
          # systemd rejects ExitType=cgroup for Type=oneshot. The current
          # successful invocation is a separate mandatory Host-native join.
          ExitType =
            if normal
            then "main"
            else "cgroup";
          KillMode = "control-group";
          TimeoutStopSec = "infinity";
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";
          NoNewPrivileges = true;
          LimitCORE = 0;
          LimitNOFILE =
            if normal
            then parent.fixedOpenFilesPerProcess
            else 256;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectProc = "invisible";
          ProcSubset = "all";
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = ["AF_UNIX"];
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          PrivateTmp = true;
          PrivateNetwork = true;
          PrivateDevices = false;
          DevicePolicy = "closed";
          DeviceAllow = ["/dev/tpmrm0 rw"];
          ReadWritePaths = ["/var/lib/aos/sandbox/runtime-deployment"];
        }
        // lib.optionalAttrs normal {
          RemainAfterExit = true;
          ExecReload = [];
          ExecCondition = [];
          StandardInput = "null";
          CPUQuota = "${toString (builtins.div (builtins.elemAt bootLimits 0) 1000)}%";
          CPUQuotaPeriodSec = "100ms";
          MemoryMax = builtins.elemAt bootLimits 1;
          TasksMax = builtins.elemAt bootLimits 2;
        };
    };

    # The Host receives only public trust/profile DATA and protected output.
    # Its native successful-oneshot observation must independently join this
    # same invocation; file presence and service ordering grant no readiness.
    systemd.services.aos-sandbox-hostd = lib.mkIf normal {
      requires = ["aos-sandbox-runtime-publisher.service"];
      after = ["aos-sandbox-runtime-publisher.service"];
      serviceConfig.LoadCredential =
        publicDelivery
        ++ [
          "aos-runtime-deployment-startup-profile:${cfg._profile}/profile.json"
          "backend-readiness.json:${readinessDirectory}/backend-readiness.json"
          "backend-readiness-completion-v1:${readinessDirectory}/backend-readiness-completion-v1"
        ];
    };
    systemd.tmpfiles.rules = lib.optionals normal [
      "d ${readinessDirectory} 0700 root root - -"
    ];
  };
}
