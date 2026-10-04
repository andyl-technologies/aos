##! Closed online Nix owner; all floor, Store and GC-root provisioning is external.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.nixBroker;
  controller = config.aos.sandbox.controller;
  controllerService = config.aos.sandbox.controllerService;
  selinux = config.aos.security.selinux;
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  selectedPackage = if cfg.enable then pkgs.aosNixOnlineControllerWith {
    domainIdHex = if cfg.domainIdHex == null
      then throw "online Resolve50 requires an explicit nonzero domain16"
      else cfg.domainIdHex;
  } else null;
  identities = [controller.uid controller.gid cfg.builderUid cfg.builderGid];
  publicNames = [
    "nix-recipe-issuer-v2"
    "nix-fixed-domain-pins-v2"
    "nix-broker-session-manifest-v1"
    "nix-preadmitted-recipes-v2"
    "ownership-lease-policy.cbor"
    "ownership-lease-public-key"
    "broker-plan-policy.cbor"
    "broker-plan-public-key"
    "broker-revocation-scope"
    "mount-broker-plan-policy.cbor"
    "mount-broker-plan-public-key"
    "mount-broker-revocation-scope"
  ];
  credential = description: lib.mkOption {
    type = lib.types.nullOr lib.serviceTypes.credentialName;
    default = null;
    inherit description;
  };
  floorOptions = {
    issuer = credential "Independent raw48 ONLINE purpose issuer pin; never an offline or method46 approval.";
    auth = credential "Independent nonzero32 ONLINE purpose authentication/NV authorization secret.";
    genesis = credential "Independent signed904 AOSNXG02 initialized full-map/NV cut, including signed640 seed; runtime never initializes it.";
  };
  brokerSession = import ./_broker-session-credentials.nix {inherit lib pkgs;};
  endpoints = [{
    name = "nix-online";
    description = "fixed ONLINE059 Resolve50 owner";
    role = "broker";
    required = true;
    journalRoot = "/var/lib/aos/sandbox-nix/broker-session/controller";
    options = {manifest = "manifest"; hello = "hello"; record = "record";};
  }];
  clientEndpoints = [{
    name = "nix-online-client";
    description = "fixed ONLINE058 Controller Resolve50 client";
    role = "client";
    required = true;
    journalRoot = "/var/lib/aos/sandboxd/broker-session/nix";
    options = {manifest = "clientManifest"; hello = "clientHello"; record = "clientRecord";};
  }];
  endpointConfiguration = brokerSession.configure cfg.credentials endpoints;
  clientConfiguration = brokerSession.configure cfg.credentials clientEndpoints;
  delivery = ["node-id:/run/credentials/@system/${controllerService.credentials.nodeId}"]
    ++ map (name: "${name}:/run/credentials/@system/${cfg.publicCredentials.${name}}") publicNames
    ++ [
      "nix-online-floor-issuer-v1:/run/credentials/@system/${cfg.ownerFloor.issuer}"
      "nix-online-floor-auth-v1:/run/credentials/@system/${cfg.ownerFloor.auth}"
      "nix-online-floor-genesis-v1:/run/credentials/@system/${cfg.ownerFloor.genesis}"
      "nix-online-store-snapshot-v1:/run/credentials/@system/${cfg.storeSnapshot}"
    ] ++ lib.optional cfg.existingOutputs
      "nix-online-output-snapshot-v1:/run/credentials/@system/${cfg.outputSnapshot}"
      ++ endpointConfiguration.loadCredentials;

  # Normalize only the profile self-reference. Final selected environment and
  # job scripts remain in the signed startup comparison, without a build cycle.
  normalizedUnit = role: let
    owner = role == "owner";
    unit = if owner then config.systemd.services.aos-sandbox-nixd
      else config.systemd.services.aos-sandboxd;
    name = if owner then "aos-nix-owner-profile" else "aos-nix-controller-profile";
    otherFiles = if owner then [] else
      lib.optional (config.aos.sandbox.policyAuthority.enable)
      "${config.aos.sandbox.policyAuthority._normalStartupProfile}/profile.json:aos-normal-root-client-profile:read-only";
    normalized = unit // {
      environment = config.systemd.globalEnvironment // unit.environment;
      serviceConfig = unit.serviceConfig // {
        OpenFile = otherFiles ++ [
          (if owner then "/proc/1/exe:aos-nix-owner-pid1-image:read-only"
            else "/proc/1/exe:aos-nix-controller-pid1-image:read-only")
          "@AOS_NIX_PROFILE@:${name}:read-only"
        ];
      };
    };
    rendered = systemdLib.serviceToUnit normalized;
  in builtins.replaceStrings
    (map (job: job.placeholder) rendered.jobScripts)
    (map (job: job.path) rendered.jobScripts) rendered.text;
  profile = role: pkgs.aosNixStartupProfileWith {
    inherit role identities;
    aos-sandboxd = selectedPackage;
    systemd = config.systemd.package;
    aos-selinux-production-policy = selinux._productionPolicy;
    aos-selinux-kernel-policy-readback = selinux._canonicalReadback;
    unitContract = normalizedUnit role;
  };
in {
  options.aos.sandbox.nixBroker = {
    enable = lib.mkEnableOption "the installed online Resolve50 consumer and optional existing-output 51/52 continuation; no builder or NV initialization";
    existingOutputs = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Select one independently granted existing-output Realize51 and Query52 after Resolve50; not a builder, floor initializer, publication or successful Start.";
    };
    domainIdHex = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Explicit nonzero lowercase32 raw domain16 DATA matching independent FixedDomainPinsV2; never read from a credential during evaluation.";
    };
    builderUid = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = "Independent nonroot later-builder UID; control owner remains root0/cap0xc0.";
    };
    builderGid = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = "Independent nonroot later-builder GID; Resolve50 launches no builder.";
    };
    credentials = brokerSession.mkOptions (endpoints ++ clientEndpoints);
    publicCredentials = lib.genAttrs publicNames (name: credential "Independent original ${name}, delivered separately to the fixed owner; signature/currentness checks remain runtime requirements.");
    controllerFloor = floorOptions;
    ownerFloor = floorOptions;
    storeSnapshot = credential "Independent complete signed AOSNXV01 fs-verity store/DB/name/alias snapshot; metadata and signing alone are not physical backing proof.";
    outputSnapshot = credential "Independent signed AOSNXV01 existing-output snapshot bound to the SAME Store root and control inodes; never generated by the runtime reader.";
    storageGenerationPrepare.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      apply = enabled:
        if enabled && !cfg.enable
        then throw "Nix generation Prepare requires the genuine enabled original Nix startup"
        else enabled;
      description = "The same-original pending Start to existing-only Storage Prepared bridge; no Clone Apply, build, publication or completed Start.";
    };
    storageGenerationPrepare.origin = credential "Independent signed AOSNXV02 complete inputs and single AOSNXG01 four-control list, bound to the exact original V1 artifact and retained current Start; signed DATA alone is not currentness.";
    _package = lib.mkOption {type = lib.types.nullOr lib.types.package; readOnly = true; default = selectedPackage; internal = true;};
    _controllerProfile = lib.mkOption {type = lib.types.nullOr lib.types.package; readOnly = true; default = if cfg.enable then profile "controller" else null; internal = true;};
    _ownerProfile = lib.mkOption {type = lib.types.nullOr lib.types.package; readOnly = true; default = if cfg.enable then profile "owner" else null; internal = true;};
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.existingOutputs || cfg.outputSnapshot != null;
        message = "existing-output Realize51 requires independently enrolled output bytes, compatible initialized ONLINE floors, and preprovisioned correctly labelled aos-online/auto GC-root directories; this module creates none";
      }
      {
        assertion = controllerService.enable && cfg.builderUid > 0 && cfg.builderGid > 0
          && config.systemd.package == pkgs.systemd
          && selinux.enable && selinux.bootMode == "immutable-stage0"
          && selinux.mode == "enforcing" && selinux.policy == "aos"
          && !config.aos.sandbox.nixOfflinePrepare.enable;
        message = "online Resolve50 requires explicitly configured immutable enforcing AOS policy/PID1, genuine Controller, nonroot builder comparisons, and no offline-mode substitution";
      }
      {
        assertion = lib.all (value: value != null) (map (name: cfg.publicCredentials.${name}) publicNames
          ++ [cfg.controllerFloor.issuer cfg.controllerFloor.auth cfg.controllerFloor.genesis
            cfg.ownerFloor.issuer cfg.ownerFloor.auth cfg.ownerFloor.genesis cfg.storeSnapshot])
          && cfg.controllerFloor.auth != cfg.ownerFloor.auth
          && cfg.controllerFloor.genesis != cfg.ownerFloor.genesis;
        message = "ONLINE058 and059 require independent externally initialized written NV/main/sidecar cuts, distinct auth/genesis and complete original public/store inputs; this module provisions no floor";
      }
      {
        assertion = !cfg.storageGenerationPrepare.enable || (
          cfg.storageGenerationPrepare.origin != null
          && config.aos.sandbox.storageBroker.enable
          && config.aos.sandbox.storageBroker.nixGenerationPrepare.enable
          && config.aos.sandbox.storageBroker.resolverPolicyDirectory != null
          && config.aos.sandbox.storageBroker.credentials.gitCoverageEnrollment == null
          && !controllerService.gitUploadBootstrap.enable
          && !controllerService.sourceSuccessorIssuance.enable
        );
        message = "Nix generation Prepare requires independently supplied signed origin/inputs and the same explicitly selected existing Storage resolver, without an exclusive Git cohort or Source issue mode";
      }
      {
        assertion = cfg.publicCredentials."ownership-lease-policy.cbor" == config.aos.sandbox.hostBroker.credentials.ownershipLeasePolicy
          && cfg.publicCredentials."ownership-lease-public-key" == config.aos.sandbox.hostBroker.credentials.ownershipLeasePublicKey
          && cfg.publicCredentials."broker-plan-policy.cbor" == config.aos.sandbox.hostBroker.credentials.brokerPlanPolicy
          && cfg.publicCredentials."broker-plan-public-key" == config.aos.sandbox.hostBroker.credentials.brokerPlanPublicKey
          && cfg.publicCredentials."broker-revocation-scope" == config.aos.sandbox.hostBroker.credentials.brokerRevocationScope
          && cfg.publicCredentials."mount-broker-plan-policy.cbor" == config.aos.sandbox.mountBroker.credentials.brokerPlanPolicy
          && cfg.publicCredentials."mount-broker-plan-public-key" == config.aos.sandbox.mountBroker.credentials.brokerPlanPublicKey
          && cfg.publicCredentials."mount-broker-revocation-scope" == config.aos.sandbox.mountBroker.credentials.brokerRevocationScope;
        message = "online original public delivery must match the SAME independently configured Controller twelve-public set; names alone authorize no Nix plan or lease";
      }
    ] ++ endpointConfiguration.assertions ++ clientConfiguration.assertions;

    aos.sandbox.controllerService.package = lib.mkDefault selectedPackage;
    # Selected fixed custody files are independently preinstalled. The old
    # ordinary installer is not an entry route under this closed owner context;
    # runtime still compares delivered credentials to the actual fixed files.
    systemd.services.aos-sandboxd.serviceConfig = {
      LoadCredential = clientConfiguration.loadCredentials;
    };
    systemd.services.aos-sandboxd.environment = lib.mkIf cfg.existingOutputs {
      AOS_NIX_EXISTING_OUTPUTS = "1";
    };
    environment.etc."tmpfiles.d/aos-sandbox-nix.conf".text = ''
      d /run/aos/sandbox-nix 0710 root aos-sandboxd - -
    '';
    systemd.sockets.aos-sandbox-nixd-control = {
      description = "Fixed original online Nix Resolve50 record listener";
      wantedBy = ["sockets.target"];
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-nix/control.sock";
        FileDescriptorName = "aos-sandbox-nixd-control";
        Service = "aos-sandbox-nixd.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-sandboxd";
        SocketMode = "0600";
        DirectoryMode = "0710";
        SendBuffer = "4M";
        RemoveOnStop = true;
      };
    };
    systemd.services.aos-sandbox-nixd = {
      description = "Retained original ONLINE059 Resolve50 owner";
      requires = ["aos-sandbox-nixd-control.socket" "dbus.service"];
      after = ["aos-sandbox-nixd-control.socket" "dbus.service"];
      unitConfig.RequiresMountsFor = ["/sys/fs/cgroup" "/var/lib/aos/sandbox-nix"];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${selectedPackage}/bin/aos-sandbox-nixd ${lib.concatMapStringsSep " " toString identities}${lib.optionalString cfg.existingOutputs " existing-outputs"}";
        Sockets = ["aos-sandbox-nixd-control.socket"];
        LoadCredential = delivery;
        OpenFile = [
          "/proc/1/exe:aos-nix-owner-pid1-image:read-only"
          "${cfg._ownerProfile}/owner.json:aos-nix-owner-profile:read-only"
        ];
        ExtraFileDescriptorNames = [];
        FileDescriptorStoreMax = 0;
        User = "root";
        Group = "root";
        SupplementaryGroups = "";
        DynamicUser = false;
        SELinuxContext = "system_u:system_r:aos_sandbox_nix_t";
        CapabilityBoundingSet = ["CAP_SETUID" "CAP_SETGID"];
        AmbientCapabilities = "";
        SecureBits = "no-setuid-fixup no-setuid-fixup-locked";
        NoNewPrivileges = true;
        ExitType = "cgroup";
        KillMode = "control-group";
        TimeoutStopSec = "infinity";
        Restart = "no";
        Slice = "aos-control.slice";
        UMask = "0077";
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/tpmrm0 rw"];
        PrivateDevices = false;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProcSubset = "all";
        ProtectProc = "default";
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectClock = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        MemoryDenyWriteExecute = true;
        LockPersonality = true;
        LimitCORE = 0;
        LimitNOFILE = 16384;
        MemoryMax = "4G";
        MemorySwapMax = 0;
        TasksMax = 16;
        ReadWritePaths = ["/var/lib/aos/sandbox-nix/broker-session/controller"]
          ++ lib.optionals cfg.existingOutputs [
            "/var/lib/aos/sandbox-nix/domains/${cfg.domainIdHex}/root/nix/var/nix/gcroots/aos-online"
            "/var/lib/aos/sandbox-nix/domains/${cfg.domainIdHex}/root/nix/var/nix/gcroots/auto"
          ];
        BindReadOnlyPaths = ["/var/lib/aos/sandbox-nix/domains/${cfg.domainIdHex}/root"];
        StateDirectory = [];
        RuntimeDirectory = [];
      };
    };
  };
}
