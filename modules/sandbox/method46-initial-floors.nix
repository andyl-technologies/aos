##! Installs fixed manual floor producers without initializing on normal startup.
{
  config,
  lib,
  pkgs,
  ...
}: let
  sandbox = config.aos.sandbox;
  cfg = sandbox.method46InitialFloors;
  parent = sandbox.resourceBank.parentEnclosure;
  selinux = config.aos.security.selinux;
  credentialNameType = import ./_credential-name-type.nix {inherit lib;};
  commands = import ./_normal-floor-service-commands.nix {inherit config lib;};
  systemdLib = import ../../pkgs/system/_systemd-abilities/platform/render.nix {inherit lib pkgs;};
  services = config.systemd.services;
  roles = {
    controller = {
      unit = "aos-sandbox-controller-floor-initialize";
      normal = "aos-sandboxd";
      normalPackage = sandbox.controllerService.package;
      normalManifest = "storage-manifest";
      directory = "/var/lib/aos/sandboxd/broker-session/storage";
      socket = "/run/aos/sandbox/method46-controller-initial.sock";
      receiving = "method46ControllerInitialReceiving";
      sender = "method46ControllerInitialSender";
      normalEnabled = sandbox.controllerService.enable;
      floorRequired = sandbox.controllerService.method46TpmFloor.required;
    };
    storage = {
      unit = "aos-sandbox-storage-floor-initialize";
      normal = "aos-storaged";
      normalPackage = sandbox.storageBroker.package;
      normalManifest = "storage-broker-manifest";
      directory = "/var/lib/aos/sandbox-storage/broker-session";
      socket = "/run/aos/sandbox/method46-storage-initial.sock";
      receiving = "method46StorageInitialReceiving";
      sender = "method46StorageInitialSender";
      normalEnabled = sandbox.storageBroker.enable;
      floorRequired = sandbox.storageBroker.method46TpmFloor.required;
    };
  };
  selected = lib.filterAttrs (purpose: _: cfg.${purpose}.enable) roles;

  # Borrow only these public normal-owner deliveries. Private signing keys never
  # enter the initializer roster; its sole private input is its own index auth.
  publicDeliveries = [
    ["method46-normal-host-manifest-v1" "aos-sandboxd" "host-manifest"]
    ["method46-normal-mount-manifest-v1" "aos-sandboxd" "mount-manifest"]
    ["method46-normal-network-manifest-v1" "aos-sandboxd" "network-manifest"]
    ["method46-normal-mount-fuse-manifest-v1" "aos-sandboxd" "mount-fuse-manifest"]
    ["method46-normal-nix-manifest-v1" "aos-sandboxd" "nix-broker-session-manifest-v1"]
    ["method46-normal-controller-nix-floor-issuer-v1" "aos-sandboxd" "nix-online-floor-issuer-v1"]
    ["method46-normal-root-deployment-public-key-v1" "aos-sandbox-policy-authorityd" "deployment-public-key"]
    ["method46-normal-root-project-public-key-v1" "aos-sandbox-policy-authorityd" "project-public-key"]
    ["method46-normal-root-cache-public-key-v1" "aos-sandbox-policy-authorityd" "cache-owner-readback-public-key"]
    ["method46-normal-root-controller-public-key-v1" "aos-sandbox-policy-authorityd" "controller-hold-public-key"]
    ["method46-normal-root-source-public-key-v1" "aos-sandbox-policy-authorityd" "source-hold-public-key"]
    ["method46-normal-owner-nix-floor-issuer-v1" "aos-sandbox-nixd" "nix-online-floor-issuer-v1"]
    ["method46-normal-controller-nix-recipe-public-key-v1" "aos-sandboxd" "nix-recipe-issuer-v2"]
    ["method46-normal-controller-ownership-public-key-v1" "aos-sandboxd" "ownership-lease-public-key"]
    ["method46-normal-controller-host-plan-public-key-v1" "aos-sandboxd" "broker-plan-public-key"]
    ["method46-normal-controller-mount-plan-public-key-v1" "aos-sandboxd" "mount-broker-plan-public-key"]
    ["method46-normal-owner-nix-recipe-public-key-v1" "aos-sandbox-nixd" "nix-recipe-issuer-v2"]
    ["method46-normal-owner-nix-ownership-public-key-v1" "aos-sandbox-nixd" "ownership-lease-public-key"]
    ["method46-normal-owner-nix-host-plan-public-key-v1" "aos-sandbox-nixd" "broker-plan-public-key"]
    ["method46-normal-owner-nix-mount-plan-public-key-v1" "aos-sandbox-nixd" "mount-broker-plan-public-key"]
    ["method46-normal-root-ownership-public-key-v1" "aos-sandbox-policy-authorityd" "ownership-lease-public-key"]
    ["method46-normal-root-host-plan-public-key-v1" "aos-sandbox-policy-authorityd" "broker-plan-public-key"]
    ["method46-normal-root-mount-plan-public-key-v1" "aos-sandbox-policy-authorityd" "mount-broker-plan-public-key"]
    ["method46-normal-root-source-seed-issuer-v1" "aos-sandbox-policy-authorityd" "controller-source-tree-seed-issuer-v1"]
    ["method46-normal-root-project-authorization-issuer-v2" "aos-sandbox-policy-authorityd" "project-authorization-issuer-v2"]
    ["method46-normal-controller-source-seed-issuer-v1" "aos-sandboxd" "controller-source-tree-seed-issuer-v1"]
    ["method46-normal-controller-project-authorization-issuer-v2" "aos-sandboxd" "project-authorization-issuer-v2"]
    ["method46-normal-root-noapply-public-key-v2" "aos-sandbox-hostd" "root-noapply-floor-public"]
    ["method46-normal-owner-nix-catalog-manifest-v1" "aos-sandbox-nixd" "nix-broker-session-manifest-v1"]
    ["method46-normal-owner-nix-online-manifest-v1" "aos-sandbox-nixd" "nix-online-manifest"]
    ["method46-normal-controller-nix-online-manifest-v1" "aos-sandboxd" "nix-online-client-manifest"]
    ["method46-normal-owner-host-manifest-v1" "aos-sandbox-hostd" "host-broker-manifest"]
  ];
  requiredNames = [
    "broker-method46-tpm-provision-v1"
    "broker-method46-tpm-index-auth-v1"
    "method46-initial-approval-public-key-v1"
    "method46-normal-storage-manifest-v1"
    "method46-normal-host-manifest-v1"
    "method46-normal-mount-manifest-v1"
    "method46-normal-network-manifest-v1"
    "method46-normal-root-deployment-public-key-v1"
    "method46-normal-root-project-public-key-v1"
    "method46-normal-controller-ownership-public-key-v1"
    "method46-normal-controller-host-plan-public-key-v1"
    "method46-normal-controller-mount-plan-public-key-v1"
    "method46-normal-owner-host-manifest-v1"
  ];
  sourceFor = service: name: let
    entries =
      lib.filter (lib.hasPrefix "${name}:")
      (services.${service}.serviceConfig.LoadCredential or []);
  in
    if entries == []
    then null
    else if builtins.length entries == 1
    then lib.removePrefix "${name}:" (builtins.head entries)
    else throw "initial-floor delivery requires one actual ${service}/${name} source";
  borrow = alias: service: name: let
    source = sourceFor service name;
  in
    lib.optional (source != null) "${alias}:${source}";
  deliveryFor = purpose: role:
    borrow "broker-method46-tpm-provision-v1" role.normal "broker-method46-tpm-provision-v1"
    ++ borrow "broker-method46-tpm-index-auth-v1" role.normal "broker-method46-tpm-index-auth-v1"
    ++ lib.optional (cfg.${purpose}.approvalPublicKeyCredential != null)
    "method46-initial-approval-public-key-v1:/run/credentials/@system/${cfg.${purpose}.approvalPublicKeyCredential}"
    ++ borrow "method46-normal-storage-manifest-v1" role.normal role.normalManifest
    ++ lib.concatMap (row: borrow (builtins.elemAt row 0) (builtins.elemAt row 1) (builtins.elemAt row 2)) publicDeliveries;

  profileFor = purpose: role: let
    selectedService = services.${role.unit};
    normalized =
      selectedService
      // {
        environment = config.systemd.globalEnvironment // selectedService.environment;
        serviceConfig =
          selectedService.serviceConfig
          // {
            OpenFile = [
              "/proc/1/exe:aos-method46-initial-pid1-image:read-only"
              "@AOS_METHOD46_INITIAL_STARTUP_PROFILE@:aos-method46-initial-startup-profile:read-only"
            ];
          };
      };
    rendered = systemdLib.serviceToUnit normalized;
    unitContract =
      builtins.replaceStrings
      (map (job: job.placeholder) rendered.jobScripts)
      (map (job: job.path) rendered.jobScripts)
      rendered.text;
    normalName = "${role.normal}.service";
    normalBody = config.system.build.systemdUnitBodies.${normalName};
    # Materialize the actual single normal leaf with the same renderer as the
    # full manager. Its resolved per-unit inode/path matches the installed link,
    # without making the profile depend on its own aggregate manager output.
    normalFragments = systemdLib.materializeUnits {
      type = "system";
      etc = {
        "systemd/system/${normalName}" = config.system.build.systemdEtcEntries."systemd/system/${normalName}";
      };
      jobScripts = lib.genAttrs normalBody.jobScriptKeys (key: config.system.build.systemdJobScripts.${key});
    };
  in
    pkgs.aosMethod46InitialStartupProfileWith {
      inherit purpose unitContract;
      initialPackage = cfg.package;
      normalPackage = role.normalPackage;
      normalUnitFragment = "${normalFragments}/${normalName}";
      normalArgv = commands.${purpose}.argv;
      controllerUid = sandbox.controller.uid;
      controllerGid = sandbox.controller.gid;
      approvalPublicKey = cfg.${purpose}.approvalPublicKey;
      systemd = config.aos.manager.selected.package;
      aos-selinux-production-policy = selinux._productionPolicy;
      aos-selinux-kernel-policy-readback = selinux._canonicalReadback;
    };
  profiles = lib.mapAttrs profileFor selected;
  validSystemSource = entry: let
    source = lib.concatStringsSep ":" (builtins.tail (lib.splitString ":" entry));
    prefix = "/run/credentials/@system/";
    name = lib.removePrefix prefix source;
  in
    lib.hasPrefix prefix source
    && builtins.match "[A-Za-z0-9_.-]+" name != null
    && name != "."
    && name != ".."
    && builtins.stringLength name <= 255;
in {
  options.aos.sandbox.method46InitialFloors =
    {
      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.aos-method46-floor-initializers;
        defaultText = "pkgs.aos-method46-floor-initializers";
        description = "The separate fixed manual initial-floor binaries; normal daemons never select this entry graph.";
      };
    }
    // lib.genAttrs ["controller" "storage"] (purpose: {
      enable = lib.mkEnableOption "the fixed manual ${purpose} initial-floor service and approval socket";
      approvalPublicKeyCredential = lib.mkOption {
        type = lib.types.nullOr credentialNameType;
        default = null;
        description = "External system credential containing this purpose's independent 32-byte approval public key. No private approver key is delivered to this host service.";
      };
      approvalPublicKey = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf (lib.types.ints.between 0 255));
        default = null;
        description = "The same 32 public approval bytes committed by the immutable startup profile; runtime compares the external credential and rejects normal-owner key reuse.";
      };
    });

  config = lib.mkMerge [
    {
      assertions =
        lib.mapAttrsToList (purpose: role: {
          assertion =
            cfg.${purpose}.enable
            == (parent != null && parent.${role.receiving} != null)
            && cfg.${purpose}.enable == (parent != null && parent.${role.sender} != null);
          message = "Manual ${purpose} initial-floor definitions and both Parent06 subdivisions must be selected together; a reserved role cannot become an empty service.";
        })
        roles;
    }
    (lib.mkIf (selected != {}) {
      assertions = lib.concatLists (lib.mapAttrsToList (purpose: role: let
          service = services.${role.unit};
          socket = config.systemd.sockets.${role.unit};
          delivery = deliveryFor purpose role;
          names = map (entry: builtins.head (lib.splitString ":" entry)) delivery;
        in [
          {
            assertion = parent != null && parent.${role.receiving} != null && parent.${role.sender} != null;
            message = "Manual ${purpose} floor initialization requires explicit, separate Parent06 receiving and sender subdivisions.";
          }
          {
            assertion =
              role.normalEnabled
              && role.floorRequired
              && sandbox.controllerService.enable
              && sandbox.storageBroker.enable
              && sandbox.policyAuthority.enable
              && sandbox.hostBroker.enable
              && (import ./_fixed-systemd-profile.nix {inherit config pkgs;});
            message = "Manual ${purpose} floor initialization requires the canonical manager, both actual normal owners and public Root/Host provenance; its normal endpoint must require its floor.";
          }
          {
            assertion = selinux.enable && selinux.mode == "enforcing" && selinux.bootMode == "immutable-stage0";
            message = "Manual initial-floor services require immutable enforcing MAC; standalone/non-enforcing execution cannot provision their floors.";
          }
          {
            assertion = builtins.elem purpose (selinux._productionPolicy.passthru.method46InitialPurposes or []);
            message = "Manual ${purpose} floor initialization requires the selected production policy's independent service/helper roles and fixed image labels.";
          }
          {
            assertion =
              cfg.${purpose}.approvalPublicKeyCredential
              != null
              && cfg.${purpose}.approvalPublicKey != null
              && builtins.length cfg.${purpose}.approvalPublicKey == 32
              && lib.any (byte: byte != 0) cfg.${purpose}.approvalPublicKey
              && lib.all (name: builtins.elem name names) requiredNames
              && lib.all validSystemSource delivery;
            message = "Manual ${purpose} floor initialization requires its independent public approval pin and the actual normal owners' complete external public credential sources.";
          }
          {
            assertion =
              role.normalEnabled
              && service.wantedBy
              == []
              && service.requiredBy == []
              && socket.wantedBy == []
              && socket.requiredBy == []
              && (service.serviceConfig.ExecStart or null) == "${cfg.package}/bin/${role.unit}"
              && (service.serviceConfig.ExecStartPre or []) == []
              && (service.serviceConfig.ExecStartPost or []) == []
              && (service.serviceConfig.OpenFile or [])
              == [
                "/proc/1/exe:aos-method46-initial-pid1-image:read-only"
                "${profiles.${purpose}}/profile.json:aos-method46-initial-startup-profile:read-only"
              ]
              && (service.serviceConfig.Sockets or []) == ["${role.unit}.socket"]
              && (service.serviceConfig.StandardInput or null) == "null"
              && (service.serviceConfig.ExtraFileDescriptorNames or []) == []
              && (service.serviceConfig.FileDescriptorStoreMax or null) == 0
              && (service.serviceConfig.LoadCredential or []) == delivery;
            message = "Manual initial-floor units must remain unbootstrapped, argument-free and bound to their exact original delivery; normal startup cannot initialize.";
          }
        ])
        selected);

      systemd.services = lib.mapAttrs' (purpose: role:
        lib.nameValuePair role.unit {
          description = "Manual independently approved ${purpose} journal-floor initialization";
          wantedBy = [];
          requiredBy = [];
          requires = ["dbus.service" "${role.unit}.socket"];
          after = ["dbus.service" "${role.unit}.socket"];
          environment.DBUS_SYSTEM_BUS_ADDRESS = "unix:path=/run/dbus/system_bus_socket";
          serviceConfig = {
            Type = "exec";
            ExecStart = "${cfg.package}/bin/${role.unit}";
            Restart = "no";
            User = "root";
            Group = "root";
            SupplementaryGroups = "";
            DynamicUser = false;
            PrivateUsers = false;
            Slice = "aoscomponents.slice";
            SELinuxContext = "system_u:system_r:aos_method46_${purpose}_initial_t";
            LoadCredential = deliveryFor purpose role;
            OpenFile = [
              "/proc/1/exe:aos-method46-initial-pid1-image:read-only"
              "${profiles.${purpose}}/profile.json:aos-method46-initial-startup-profile:read-only"
            ];
            Sockets = ["${role.unit}.socket"];
            StandardInput = "null";
            StandardOutput = "journal";
            StandardError = "inherit";
            ExtraFileDescriptorNames = [];
            FileDescriptorStoreMax = 0;
            StateDirectory = [];
            RuntimeDirectory = [];
            CapabilityBoundingSet = ["CAP_CHOWN" "CAP_DAC_OVERRIDE"];
            AmbientCapabilities = "";
            NoNewPrivileges = true;
            SecureBits = "no-setuid-fixup no-setuid-fixup-locked";
            ExitType = "cgroup";
            KillMode = "control-group";
            TimeoutStopSec = "infinity";
            LimitCORE = 0;
            UMask = "0077";
            DevicePolicy = "closed";
            DeviceAllow = ["/dev/tpmrm0 rw"];
            PrivateDevices = false;
            PrivateNetwork = true;
            PrivateTmp = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            ProtectProc = "default";
            ProcSubset = "all";
            ProtectControlGroups = true;
            ProtectKernelLogs = true;
            ProtectKernelModules = true;
            ProtectKernelTunables = true;
            ProtectClock = true;
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            RestrictAddressFamilies = ["AF_UNIX"];
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            ReadWritePaths = [role.directory];
          };
        })
      selected;

      # Installing the definitions does not start these sockets. An operator
      # selects the manual interval; PID1's original exclusion gates refuse active
      # normal writers and the other initializer without stopping them implicitly.
      systemd.sockets = lib.mapAttrs' (_purpose: role:
        lib.nameValuePair role.unit {
          description = "Fixed ${role.unit} independent approval listener";
          wantedBy = [];
          requiredBy = [];
          socketConfig = {
            ListenSequentialPacket = role.socket;
            FileDescriptorName = "aos-method46-initial-approval";
            Service = "${role.unit}.service";
            Accept = false;
            SocketUser = "root";
            SocketGroup = "root";
            SocketMode = "0600";
            DirectoryMode = "0700";
            Backlog = 1;
            PassCredentials = true;
            PassPIDFD = true;
            PassSecurity = false;
            PassSubjectBeforeListen = true;
          };
        })
      selected;
    })
  ];
}
