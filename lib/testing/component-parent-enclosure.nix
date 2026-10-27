##! Checks nullable parent-enclosure projections through actual receiving schemas.
##!
##! These typed fixtures exercise definition collection without materializing
##! an enclosure or admitting a resource policy or runtime effect.
{lib}: let
  auditBounds = {
    maxLogFileMiB = 1;
    numLogs = 2;
    maximumRules = 1;
    maximumRuleBytes = 1;
    maximumBacklog = 1;
  };
  profile = {
    manager = {};
    fixedServices = {
      cpu-micros-per-period = 1000;
      memory-bytes = 4096;
      pids = 1;
    };
    managerOpenFilesPerProcess = 1;
    fixedOpenFilesPerProcess = 1;
    journal = {
      systemMaxUse = 1048576;
      systemMaxFileSize = 1048576;
      runtimeMaxUse = 1;
      runtimeMaxFileSize = 1;
    };
    audit = auditBounds;
  };
  evaluate = parentEnclosure: extraModules:
    (lib.evalModules {
      inherit lib;
      modules =
        [
          ../../modules/sandbox/component-parent-enclosure.nix
          ({
            config,
            lib,
            pkgs,
            provenance,
            ...
          }: let
            auditModule = import ../../pkgs/security/_audit/policy.nix {inherit lib;};
            journalModule = import ../../pkgs/system/_aos-host-policy/journald.nix {inherit lib;};
            systemdModule = import ../../pkgs/system/_systemd-abilities/platform/system.nix {inherit config lib pkgs provenance;};
            serviceModule = import ../../pkgs/system/_service-management/module.nix {
              inherit lib;
              config.aos.abilities.serviceManagement.operations.realize.input = ../../pkgs/system/_service-management/input.nix;
            };
            mountModule = import ../../modules/sandbox/mount-broker.nix {inherit config lib pkgs;};
            networkModule = import ../../modules/sandbox/network-broker.nix {inherit config lib pkgs;};
            publisherModule = import ../../modules/sandbox/runtime-deployment-publisher.nix {inherit config lib pkgs;};
            hostModule = import ../../modules/sandbox/host-broker.nix {inherit config lib pkgs;};
          in {
            # Use actual receiving schemas without materializing their effects.
            options.aos.security.audit.bounds = auditModule.options.aos.security.audit.bounds;
            options.aos.security.audit.enable = auditModule.options.aos.security.audit.enable;
            options.aos.journald = journalModule.options.aos.journald;
            # Read the canonical service schema with its real operation input.
            # Its effect-producing config is not part of this projection test.
            options.aos.services = serviceModule.options.aos.services;
            options.systemd.services = systemdModule.options.systemd.services;
            options.systemd.slices = systemdModule.options.systemd.slices;
            options.systemd.sockets = systemdModule.options.systemd.sockets;
            options.systemd.packagedBaseUnits = systemdModule.options.systemd.packagedBaseUnits;
            options.aos.sandbox =
              lib.genAttrs [
                "sourceSignerService"
                "ownershipAuthority"
                "sourceSignerView"
                "cacheSignerService"
                "cacheSignerView"
                "policyAuthority"
              ] (_: {
                enable = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                };
              })
              // {
                # This fixture bypasses Dendritic discovery. Reuse the real
                # schemas for every newer role read by the enclosure module;
                # missing production declarations must not become `or false`.
                mountBroker.enable = mountModule.options.aos.sandbox.mountBroker.enable;
                networkBroker.enable = networkModule.options.aos.sandbox.networkBroker.enable;
                runtimeDeploymentPublisher = {
                  inherit (publisherModule.options.aos.sandbox.runtimeDeploymentPublisher) enable bootPreparation;
                };
                hostBroker = {
                  inherit (hostModule.options.aos.sandbox.hostBroker) componentControl executionReceiving;
                };
              };
            options.environment.etc = lib.mkOption {
              type = lib.types.attrs;
              default = {};
            };
            options.fixture.ownership = lib.mkOption {type = lib.types.attrs;};
            config.fixture.ownership = {
              service = provenance.ownerOfAttr ["systemd" "services"] "systemd-journald";
              slice = provenance.ownerOfAttr ["systemd" "slices"] "aoscomponents";
              journal =
                lib.genAttrs journalFields (name:
                  provenance.ownerOfOption ["aos" "journald" name]);
            };
          })
          {aos.sandbox.resourceBank.parentEnclosure = parentEnclosure;}
        ]
        ++ extraModules;
    })
    .config;

  disabled = evaluate null [];
  independent = evaluate null [
    {
      aos.security.audit.bounds = auditBounds;
      aos.journald = independentJournal;
      systemd.services.systemd-journald.serviceConfig = independentService;
      systemd.slices.aoscomponents.sliceConfig = independentSlice;
    }
  ];
  selected = evaluate profile [];
  mountSelected = evaluate (profile // {mountReceiving = profile.fixedServices;}) [
    {aos.sandbox.mountBroker.enable = true;}
  ];
  networkSelected = evaluate (profile // {networkReceiving = profile.fixedServices;}) [
    {aos.sandbox.networkBroker.enable = true;}
  ];
  # Both manual roles must project their own subdivisions, independently of
  # the enclosing F limit and each other. This only checks unit definitions;
  # it neither materializes a bank nor claims that a programme fits its grant.
  initialController = {
    cpu-micros-per-period = 2000;
    memory-bytes = 8192;
    pids = 2;
  };
  initialStorage = {
    cpu-micros-per-period = 3000;
    memory-bytes = 12288;
    pids = 3;
  };
  initialSelected = evaluate (profile
    // {
      fixedServices = {
        cpu-micros-per-period = 10000;
        memory-bytes = 65536;
        pids = 16;
      };
      method46ControllerInitialReceiving = initialController;
      method46ControllerInitialSender = {};
      method46StorageInitialReceiving = initialStorage;
      method46StorageInitialSender = {};
    }) [];
  controllerInitialOnly = evaluate (profile
    // {
      method46ControllerInitialReceiving = initialController;
      method46ControllerInitialSender = {};
    }) [];
  storageInitialOnly = evaluate (profile
    // {
      method46StorageInitialReceiving = initialStorage;
      method46StorageInitialSender = {};
    }) [];
  invalid = evaluate (profile // {audit = auditBounds // {numLogs = 1;};}) [];
  invalidBounds = builtins.tryEval (builtins.deepSeq invalid.aos.security.audit.bounds true);
  boundsData = value: builtins.removeAttrs value ["_module"];
  journalFields = ["maxUseBytes" "maxFileSizeBytes" "runtimeMaxUse" "runtimeMaxFileSize"];
  project = names: value: lib.genAttrs names (name: value.${name});
  serviceFields = ["CPUQuota" "MemoryMax" "TasksMax" "LimitNOFILE"];
  sliceFields = ["CPUQuota" "MemoryMax" "TasksMax"];
  expectedSlice = {
    CPUQuota = "1%";
    MemoryMax = 4096;
    TasksMax = 1;
  };
  expectedService = expectedSlice // {LimitNOFILE = 1;};
  expectedSocket = {
    PassCredentials = true;
    PassPIDFD = true;
    PassSecurity = false;
    PassSubjectBeforeListen = true;
  };
  independentSlice = {
    CPUQuota = "2%";
    MemoryMax = 8192;
    TasksMax = 2;
  };
  independentService = independentSlice // {LimitNOFILE = 2;};
  independentJournal = {
    maxUseBytes = 3 * 1048576;
    maxFileSizeBytes = 4 * 1048576;
    runtimeMaxUse = 2;
    runtimeMaxFileSize = 3;
  };
  expectedOwnership = {
    service = "@base";
    slice = "@base";
    journal = lib.genAttrs journalFields (_: "@base");
  };
in
  disabled.aos.security.audit.bounds
  == null
  && disabled.environment.etc == {}
  && disabled.systemd.services == {}
  && disabled.systemd.packagedBaseUnits == []
  # Lazy service maps retain dormant keys; they must neither enable a native
  # service nor request its immutable bootstrap base without a selected Parent.
  && builtins.all (service: !service.enable && !service.bootstrap)
  (builtins.attrValues disabled.aos.services)
  && disabled.systemd.slices == {}
  && disabled.aos.journald.maxUseBytes == 500 * 1048576
  && disabled.aos.journald.maxFileSizeBytes == 50 * 1048576
  && disabled.aos.journald.runtimeMaxUse == null
  && disabled.aos.journald.runtimeMaxFileSize == null
  && disabled.fixture.ownership == expectedOwnership
  && boundsData independent.aos.security.audit.bounds == auditBounds
  && independent.environment.etc == {}
  && builtins.all (service: !service.enable && !service.bootstrap)
  (builtins.attrValues independent.aos.services)
  && independent.systemd.packagedBaseUnits == []
  && project journalFields independent.aos.journald == independentJournal
  && project serviceFields independent.systemd.services.systemd-journald.serviceConfig == independentService
  && project sliceFields independent.systemd.slices.aoscomponents.sliceConfig == independentSlice
  && independent.fixture.ownership == expectedOwnership
  && boundsData selected.aos.security.audit.bounds == auditBounds
  && project sliceFields selected.systemd.slices.aoscomponents.sliceConfig == expectedSlice
  && builtins.attrNames selected.systemd.services
  == ["aos-journald-runtime-prep" "audit-rules" "auditd" "systemd-journald"]
  && selected.systemd.packagedBaseUnits == ["systemd-journald.service"]
  && builtins.attrNames selected.aos.services == ["audit.audit-rules" "audit.auditd"]
  && selected.aos.services."audit.audit-rules".bootstrap
  && selected.aos.services."audit.auditd".bootstrap
  && selected.systemd.services.audit-rules.overrideStrategy == "asDropin"
  && selected.systemd.services.auditd.overrideStrategy == "asDropin"
  && builtins.all (service:
    project serviceFields service.serviceConfig == expectedService)
  (builtins.attrValues selected.systemd.services)
  && project journalFields selected.aos.journald
  == {
    maxUseBytes = 1048576;
    maxFileSizeBytes = 1048576;
    runtimeMaxUse = 1;
    runtimeMaxFileSize = 1;
  }
  && selected.fixture.ownership == expectedOwnership
  && !disabled.aos.sandbox.mountBroker.enable
  && !disabled.aos.sandbox.networkBroker.enable
  && !disabled.aos.sandbox.runtimeDeploymentPublisher.enable
  && !disabled.aos.sandbox.runtimeDeploymentPublisher.bootPreparation
  && disabled.aos.sandbox.hostBroker.executionReceiving == null
  && disabled.systemd.sockets == {}
  && builtins.attrNames mountSelected.systemd.services
  == ["aos-journald-runtime-prep" "aos-sandbox-mountd" "audit-rules" "auditd" "systemd-journald"]
  && project (builtins.attrNames expectedSocket) mountSelected.systemd.sockets.aos-sandbox-mountd.socketConfig == expectedSocket
  && builtins.attrNames networkSelected.systemd.services
  == ["aos-journald-runtime-prep" "aos-netd" "audit-rules" "auditd" "systemd-journald"]
  && project sliceFields networkSelected.systemd.slices.aoscomponents-network.sliceConfig == expectedSlice
  && project (builtins.attrNames expectedSocket) networkSelected.systemd.sockets.aos-netd.socketConfig == expectedSocket
  && project serviceFields initialSelected.systemd.services.aos-sandbox-controller-floor-initialize.serviceConfig
  == {
    CPUQuota = "2%";
    MemoryMax = 8192;
    TasksMax = 2;
    LimitNOFILE = 1;
  }
  && project serviceFields initialSelected.systemd.services.aos-sandbox-storage-floor-initialize.serviceConfig
  == {
    CPUQuota = "3%";
    MemoryMax = 12288;
    TasksMax = 3;
    LimitNOFILE = 1;
  }
  && project sliceFields initialSelected.systemd.slices.aoscomponents.sliceConfig
  == {
    CPUQuota = "10%";
    MemoryMax = 65536;
    TasksMax = 16;
  }
  && controllerInitialOnly.systemd.services ? aos-sandbox-controller-floor-initialize
  && !(controllerInitialOnly.systemd.services ? aos-sandbox-storage-floor-initialize)
  && storageInitialOnly.systemd.services ? aos-sandbox-storage-floor-initialize
  && !(storageInitialOnly.systemd.services ? aos-sandbox-controller-floor-initialize)
  && project serviceFields controllerInitialOnly.systemd.services.aos-sandbox-controller-floor-initialize.serviceConfig
  == project serviceFields initialSelected.systemd.services.aos-sandbox-controller-floor-initialize.serviceConfig
  && project serviceFields storageInitialOnly.systemd.services.aos-sandbox-storage-floor-initialize.serviceConfig
  == project serviceFields initialSelected.systemd.services.aos-sandbox-storage-floor-initialize.serviceConfig
  && initialSelected.systemd.services.aos-sandbox-controller-floor-initialize.serviceConfig.Slice == "aoscomponents.slice"
  && initialSelected.systemd.services.aos-sandbox-storage-floor-initialize.serviceConfig.Slice == "aoscomponents.slice"
  && !invalidBounds.success
