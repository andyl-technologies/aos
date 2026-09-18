##! Systemd realization of provider-neutral host and initrd system milestones.
{
  lib,
  pkgs,
}: let
  milestones = lib.abilities.interfaces.serviceManagement.milestones;
  serviceInterfaces = lib.abilities.interfaces.serviceManagement.interfaces;
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "system-milestone-readiness";
  };
  unselected = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities.environment = {
          authority = "test";
          key = "unselected-systemd-milestones";
          stage = "host";
        };
      }
    ];
    packageModules = [
      (lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd)
    ];
  };
  requirement = selected: {
    interface = selected.identity.name;
    inherit (selected.identity) abi descriptor;
    methods = ["observe"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  expectedUnits = {
    host = {
      local-filesystems = "local-fs.target";
      multi-user = "multi-user.target";
    };
    initrd = {
      initrd-filesystems = "initrd-fs.target";
      initrd-root-filesystems = "initrd-root-fs.target";
      root-device = "initrd-root-device.target";
      switch-root = "initrd-switch-root.target";
      sysroot = "sysroot.mount";
      var = "mount-var.service";
      nix-overlay = "nix-overlay-setup.service";
      etc-overlay = "etc-overlay-setup.service";
      run-etc = "run-etc-setup.service";
      device-settle = "systemd-udev-settle.service";
      device-manager = "systemd-udevd.service";
      device-events-triggered = "systemd-udev-trigger.service";
      kernel-modules = "systemd-modules-load.service";
      boot-identity-validated = "aos-boot-identity-guard.service";
      boot-storage-unlocked = "aos-zfs-unlock.service";
      boot-integrity-failure = "aos-boot-integrity-failure.target";
      initrd-stage-executed = "aos-ability-initrd-controller.service";
      root-a-device = "dev-disk-by\\x2dpartlabel-root\\x2da.device";
      verity-root-mapping-ready = "aos-systemd-verity-root-setup.service";
      verity-root-verified = "aos-verity-root-verify.service";
    };
  };
  milestoneIds = {
    host = {
      local-filesystems = milestones.localFilesystems;
      multi-user = milestones.multiUser;
    };
    initrd = {
      initrd-filesystems = milestones.initrdFilesystems;
      initrd-root-filesystems = milestones.initrdRootFilesystems;
      root-device = milestones.rootDevice;
      switch-root = milestones.switchRoot;
      sysroot = milestones.sysroot;
      var = milestones.var;
      nix-overlay = milestones.nixOverlay;
      etc-overlay = milestones.etcOverlay;
      run-etc = milestones.runEtc;
      device-settle = milestones.deviceSettle;
      device-manager = milestones.deviceManager;
      device-events-triggered = milestones.deviceEventsTriggered;
      kernel-modules = milestones.kernelModules;
      boot-identity-validated = milestones.bootIdentityValidated;
      boot-storage-unlocked = milestones.bootStorageUnlocked;
      boot-integrity-failure = milestones.bootIntegrityFailure;
      initrd-stage-executed = milestones.initrdStageExecuted;
      root-a-device = milestones.rootADevice;
      verity-root-mapping-ready = milestones.verityRootMappingReady;
      verity-root-verified = milestones.verityRootVerified;
    };
  };
  earlySystemUnit = {
    host = "sysinit.target";
    initrd = "initrd-fs.target";
  };
  consumerModuleFor = stage: extraRequests: {
    config.aos.abilities = {
      instances.application = {};
      requirementTemplates = {
        system-milestone = requirement serviceInterfaces.systemMilestoneReadiness;
        activation-milestone = requirement serviceInterfaces.activationMilestone;
      };
      requests =
        (
          builtins.mapAttrs (milestone: _unit: {
            requirement = "system-milestone";
            consumer = "application";
            scope = [stage milestone];
            parameters.milestone = milestoneIds.${stage}.${milestone};
          })
          expectedUnits.${stage}
          // {
            early-system = {
              requirement = "activation-milestone";
              consumer = "application";
              scope = [stage "early-system"];
              parameters.milestone = "early-system";
            };
          }
        )
        // extraRequests;
    };
  };
  baseBindingsFor = stage: extraRequests:
    lib.mapAttrs' (requestName: _request:
      lib.nameValuePair "test:${stage}-${requestName}" {
        request = "consumer:${requestName}";
        implementation =
          if requestName == "early-system"
          then "systemd:activation-milestone"
          else "systemd:system-milestone-readiness";
        providerInstance = "systemd:manager";
        slot = "${stage}-${requestName}";
      })
    (consumerModuleFor stage extraRequests).config.aos.abilities.requests;
  evaluate = stage: extraRequests: bindings: abilityResolution:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-${stage}-milestones";
              inherit stage;
            };
            instances."systemd:manager" = {};
            inherit bindings;
          };
        }
      ];
      packageModules = [
        (lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd)
        {
          name = "consumer";
          module = consumerModuleFor stage extraRequests;
        }
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs abilityResolution;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  complete = stage: extraRequests: let
    baseBindings = baseBindingsFor stage extraRequests;
    pending = evaluate stage extraRequests baseBindings {};
    children = builtins.attrValues pending.config.aos.abilities.compositionPendingRequests;
    resolvedAbilityInputs = import ./_composition-resolution.nix {
      abilities = pending.config.aos.abilities;
    };
    effectBindings = builtins.listToAttrs (builtins.map (child: {
        name = "test:${child.request}";
        value = {
          request = child.request;
          implementation =
            if child.declaration.parameters.expected.milestone == "early-system"
            then "systemd:systemd-activation-milestone-effects"
            else "systemd:systemd-system-milestone-readiness-effects";
          providerInstance = "systemd:manager";
          slot = child.slot;
        };
      })
      children);
  in
    evaluate stage extraRequests (baseBindings // effectBindings) resolvedAbilityInputs;
  checkStage = stage: let
    abilities = (complete stage {}).config.aos.abilities;
    expected = expectedUnits.${stage} // {early-system = earlySystemUnit.${stage};};
    milestoneFor = name:
      if name == "early-system"
      then name
      else milestoneIds.${stage}.${name};
    requestFor = name:
      builtins.head (builtins.filter
        (request:
          request.parameters.expected.milestone == milestoneFor name)
        (builtins.attrValues abilities.compositionRequests));
    outputFor = name:
      abilities.compositionOutputs."consumer:${name}".resource.value;
    resourceFor = reference:
      builtins.head (builtins.filter
        (resource: resource.resource == reference.resource)
        (builtins.attrValues abilities.resolvedResources));
  in
    builtins.all (name:
      (requestFor name).parameters.systemd_unit.unit_name
      == expected.${name}
      && (resourceFor (outputFor name)).value.milestone == milestoneFor name
      && (resourceFor (outputFor name)).lifetime == "instance")
    (builtins.attrNames expected);
  unknownRejected =
    !(builtins.tryEval (builtins.deepSeq
      (complete "host" {
        unsupported = {
          requirement = "system-milestone";
          consumer = "application";
          scope = ["host" "unsupported"];
          parameters.milestone = "vendor.platform-ready";
        };
      }).config.aos.abilities.compositionRequests
      true)).success;
in
  assert unselected.config.aos.abilities.compositionOutputs == {};
  assert checkStage "host";
  assert checkStage "initrd";
  assert unknownRejected; true
