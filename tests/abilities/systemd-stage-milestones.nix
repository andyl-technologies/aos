##! Systemd realization of provider-neutral host and initrd system milestones.
{
  lib,
  pkgs,
}: let
  serviceInterfaces = lib.abilities.interfaces.serviceManagement.interfaces;
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "system-milestone-readiness";
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
      root-device = "initrd-root-device.target";
      switch-root = "initrd-switch-root.target";
      sysroot = "sysroot.mount";
      var = "mount-var.service";
      nix-overlay = "nix-overlay-setup.service";
      etc-overlay = "etc-overlay-setup.service";
      run-etc = "run-etc-setup.service";
      device-settle = "systemd-udev-settle.service";
      kernel-modules = "systemd-modules-load.service";
      boot-identity-validated = "aos-boot-identity-guard.service";
      boot-integrity-failure = "aos-boot-identity-failure.target";
      partition-layout-ready = "aos-repart.service";
      verity-root-verified = "aos-verity-root-verify.service";
    };
  };
  earlySystemUnit = {
    host = "sysinit.target";
    initrd = "initrd-fs.target";
  };
  consumerModuleFor = stage: {
    config.aos.abilities = {
      instances.application = {};
      requirementTemplates = {
        system-milestone = requirement serviceInterfaces.systemMilestoneReadiness;
        activation-milestone = requirement serviceInterfaces.activationMilestone;
      };
      requests =
        builtins.mapAttrs (milestone: _unit: {
          requirement = "system-milestone";
          consumer = "application";
          scope = [stage milestone];
          parameters = {inherit milestone;};
        })
        expectedUnits.${stage}
        // {
          early-system = {
            requirement = "activation-milestone";
            consumer = "application";
            scope = [stage "early-system"];
            parameters.milestone = "early-system";
          };
        };
    };
  };
  baseBindingsFor = stage:
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
    (consumerModuleFor stage).config.aos.abilities.requests;
  evaluate = stage: bindings:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        ../../modules/systemd/system.nix
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
        {
          name = "systemd";
          inherit (pkgs.systemd) version;
          module = pkgs.systemd.module + "/module.nix";
        }
        {
          name = "consumer";
          module = consumerModuleFor stage;
        }
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  complete = stage: let
    baseBindings = baseBindingsFor stage;
    pending = evaluate stage baseBindings;
    children = builtins.attrValues pending.config.aos.abilities.compositionPendingRequests;
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
    evaluate stage (baseBindings // effectBindings);
  checkStage = stage: let
    abilities = (complete stage).config.aos.abilities;
    expected = expectedUnits.${stage} // {early-system = earlySystemUnit.${stage};};
    requestFor = name:
      builtins.head (builtins.filter
        (request:
          request.parameters.expected.milestone == name)
        (builtins.attrValues abilities.compositionRequests));
    outputFor = name:
      abilities.compositionOutputs."consumer:${name}".readiness-resource.value;
    resourceFor = reference:
      builtins.head (builtins.filter
        (resource: resource.resource == reference.resource)
        (builtins.attrValues abilities.resolvedResources));
  in
    builtins.all (name:
      (requestFor name).parameters.systemd_unit.unit_name
      == expected.${name}
      && (resourceFor (outputFor name)).value.milestone == name
      && (resourceFor (outputFor name)).lifetime == "instance")
    (builtins.attrNames expected);
in
  assert checkStage "host";
  assert checkStage "initrd"; true
