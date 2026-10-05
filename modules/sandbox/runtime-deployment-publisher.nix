##! Disabled fixed Host055 association producer, not runtime/Create activation.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.runtimeDeploymentPublisher;
  storage = config.aos.sandbox.storageBroker;
  controller = config.aos.sandbox.controller;
  selinux = config.aos.security.selinux;
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  publicRoles = [
    "runtime-deployment-genesis-v1"
    "runtime-deployment-provisioner-pin-v1"
    "runtime-deployment-canary-purpose-v2"
  ];
  publicDelivery = map (role: "${role}:/run/credentials/@system/${role}") publicRoles;
  publisher = pkgs.callPackage ../../pkgs/tools/aos-sandbox-runtime-publisher.nix {
    systemd = config.systemd.package;
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
    (if storage.zfsHoldSigningKey == null then "-" else "zfs-hold-key-v1")
    (if storage.executionOutputKey == null then "-" else storage.executionOutputKey)
  ];
  render = unit: let
    rendered = systemdLib.serviceToUnit (unit // {
      environment = config.systemd.globalEnvironment // unit.environment;
    });
  in builtins.replaceStrings
    (map (job: job.placeholder) rendered.jobScripts)
    (map (job: job.path) rendered.jobScripts) rendered.text;
  publisherUnit = config.systemd.services.aos-sandbox-runtime-publisher;
  normalizedPublisher = publisherUnit // {
    serviceConfig = publisherUnit.serviceConfig // {
      OpenFile = [
        "/proc/1/exe:aos-runtime-deployment-pid1-image:read-only"
        "@AOS_RUNTIME_DEPLOYMENT_PROFILE@:aos-runtime-deployment-startup-profile:read-only"
      ];
    };
  };
  profiles = import ../../lib/runtime-deployment-startup-profile.nix {
    inherit pkgs publisher helper storageArguments;
    storage = storage.package;
    systemd = config.systemd.package;
    policy = selinux._productionPolicy;
    canonicalPolicy = selinux._canonicalReadback;
    publisherUnit = render normalizedPublisher;
    storageUnit = render config.systemd.services.aos-storaged;
  };
  externalCredential = description: lib.mkOption {
    type = lib.types.nullOr lib.serviceTypes.credentialName;
    default = null;
    inherit description;
  };
in {
  options.aos.sandbox.runtimeDeploymentPublisher = {
    enable = lib.mkEnableOption "the fixed selected canary association producer over an independently provisioned Host055 deployment";
    signingSeed = externalCredential "Independent root-only nonzero32 publisher seed, never generated or put in the Nix store.";
    indexAuth = externalCredential "Distinct external055 index-only auth32; no hierarchy, define, clear or bootstrap authority.";
    _profile = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = if cfg.enable then profiles.publisher else null;
      readOnly = true;
      internal = true;
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = storage.enable && storage.sourceOriginalWorkerStartup.enable
        && storage.package == pkgs.aos-storaged
        && storage.resolverPolicyDirectory == null
        && storage.credentials.gitCoverageEnrollment == null
        && config.systemd.package == pkgs.systemd
        && selinux.enable && selinux.bootMode == "immutable-stage0"
        && selinux.mode == "enforcing" && selinux.policy == "aos"
        && cfg.signingSeed != null && cfg.indexAuth != null
        && cfg.signingSeed != cfg.indexAuth
        && !(builtins.elem cfg.signingSeed publicRoles)
        && !(builtins.elem cfg.indexAuth publicRoles);
      message = "Host055 requires genuine fixed immutable Storage startup, independent public genesis/provisioner/Purpose delivery and separately provisioned055 main/sidecar/NV; it neither initializes nor adopts missing state";
    }];

    # Fixed public delivery supplements rather than replaces the ordinary
    # Storage credentials/argv. The scalar only requests fail-closed admission.
    systemd.services.aos-storaged = {
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
      description = "Fixed protected Storage-to-Host055 association listener";
      wantedBy = ["sockets.target"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
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
      };
    };
    systemd.services.aos-sandbox-runtime-publisher = {
      description = "One genuine canary association attempt over the original055 owners";
      requires = ["aos-sandbox-runtime-publisher.socket" "dbus.service"];
      after = ["aos-sandbox-runtime-publisher.socket" "dbus.service"];
      unitConfig.RequiresMountsFor = ["/sys/fs/cgroup" "/var/lib/aos/sandbox/runtime-deployment"];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${publisher}/bin/aos-sandbox-runtime-publisher --canary-association-v2";
        Sockets = ["aos-sandbox-runtime-publisher.socket"];
        OpenFile = [
          "/proc/1/exe:aos-runtime-deployment-pid1-image:read-only"
          "${cfg._profile}/profile.json:aos-runtime-deployment-startup-profile:read-only"
        ];
        LoadCredential = publicDelivery ++ [
          "runtime-deployment-signing-seed-v1:/run/credentials/@system/${cfg.signingSeed}"
          "runtime-deployment-tpm-index-auth-v1:/run/credentials/@system/${cfg.indexAuth}"
        ];
        ExtraFileDescriptorNames = [];
        FileDescriptorStoreMax = 0;
        User = "root";
        Group = "root";
        SupplementaryGroups = "";
        Slice = "aos-control.slice";
        SELinuxContext = "system_u:system_r:aos_runtime_deployment_publisher_t";
        UMask = "0077";
        Restart = "no";
        ExitType = "cgroup";
        KillMode = "control-group";
        TimeoutStopSec = "infinity";
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        NoNewPrivileges = true;
        LimitCORE = 0;
        LimitNOFILE = 256;
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
      };
    };
  };
}
