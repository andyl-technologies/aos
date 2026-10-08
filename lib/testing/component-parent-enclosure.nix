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
      systemMaxUse = 1;
      systemMaxFileSize = 1;
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
            auditModule = import ../../modules/security/audit.nix {inherit config lib pkgs;};
            journalModule = import ../../modules/base/journald.nix {inherit config lib pkgs;};
            systemdModule = import ../../modules/systemd/system.nix {inherit config lib pkgs provenance;};
          in {
            # Use actual receiving schemas without materializing their effects.
            options.aos.security.audit.bounds = auditModule.options.aos.security.audit.bounds;
            options.aos.security.audit.enable = auditModule.options.aos.security.audit.enable;
            options.aos.journald = journalModule.options.aos.journald;
            options.systemd.services = systemdModule.options.systemd.services;
            options.systemd.slices = systemdModule.options.systemd.slices;
            options.aos.sandbox =
              lib.genAttrs [
                "sourceSignerService"
                "sourceSignerView"
                "cacheSignerService"
                "cacheSignerView"
                "policyAuthority"
              ] (_: {
                enable = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                };
              });
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
  invalid = evaluate (profile // {audit = auditBounds // {numLogs = 1;};}) [];
  invalidBounds = builtins.tryEval (builtins.deepSeq invalid.aos.security.audit.bounds true);
  boundsData = value: builtins.removeAttrs value ["_module"];
  journalFields = ["maxUse" "systemMaxFileSize" "runtimeMaxUse" "runtimeMaxFileSize"];
  project = names: value: lib.genAttrs names (name: value.${name});
  serviceFields = ["CPUQuota" "MemoryMax" "TasksMax" "LimitNOFILE"];
  sliceFields = ["CPUQuota" "MemoryMax" "TasksMax"];
  expectedSlice = {
    CPUQuota = "1%";
    MemoryMax = 4096;
    TasksMax = 1;
  };
  expectedService = expectedSlice // {LimitNOFILE = 1;};
  independentSlice = {
    CPUQuota = "2%";
    MemoryMax = 8192;
    TasksMax = 2;
  };
  independentService = independentSlice // {LimitNOFILE = 2;};
  independentJournal = {
    maxUse = "3";
    systemMaxFileSize = "4";
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
  && disabled.systemd.slices == {}
  && disabled.aos.journald.maxUse == "500M"
  && disabled.aos.journald.systemMaxFileSize == "50M"
  && disabled.aos.journald.runtimeMaxUse == null
  && disabled.aos.journald.runtimeMaxFileSize == null
  && disabled.fixture.ownership == expectedOwnership
  && boundsData independent.aos.security.audit.bounds == auditBounds
  && independent.environment.etc == {}
  && project journalFields independent.aos.journald == independentJournal
  && project serviceFields independent.systemd.services.systemd-journald.serviceConfig == independentService
  && project sliceFields independent.systemd.slices.aoscomponents.sliceConfig == independentSlice
  && independent.fixture.ownership == expectedOwnership
  && boundsData selected.aos.security.audit.bounds == auditBounds
  && project sliceFields selected.systemd.slices.aoscomponents.sliceConfig == expectedSlice
  && builtins.attrNames selected.systemd.services
  == ["aos-journald-runtime-prep" "audit-rules" "auditd" "systemd-journald"]
  && builtins.all (service:
    project serviceFields service.serviceConfig == expectedService)
  (builtins.attrValues selected.systemd.services)
  && project journalFields selected.aos.journald
  == {
    maxUse = "1";
    systemMaxFileSize = "1";
    runtimeMaxUse = 1;
    runtimeMaxFileSize = 1;
  }
  && selected.fixture.ownership == expectedOwnership
  && !invalidBounds.success
