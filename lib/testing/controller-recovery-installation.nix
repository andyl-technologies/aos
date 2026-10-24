##! Evaluates the real recovery listener against actual installation modules.
##!
##! The enabled negative fixture uses the production server/module registry.
##! Positive selection takes independently configured resource-bank policy,
##! Root profile and credential inputs. It invents no vector, default policy,
##! substitute profile package or native recovery authority.
{
  pkgs,
  lib,
  mkSystem,
}: let
  recoveryMessage = "Operator recovery requires the selected public Controller/Root profile and excludes ordinary startup purposes; a genuine confirmed successor remains mandatory at runtime";
  recoveryAdmitted = system: let
    checks =
      builtins.filter (check: check.message == recoveryMessage)
      system.config.assertions;
  in
    builtins.length checks == 1 && (builtins.head checks).assertion;

  incomplete = mkSystem {
    systemName = "controller-recovery-incomplete";
    modules = [
      ../../systems/server.nix
      {
        aos.sandbox.controllerService = {
          enable = true;
          publicApi.enable = true;
          operatorRecoveryOnly.enable = true;
        };
      }
    ];
  };
  incompleteAssertions = assert incomplete.config.aos.sandbox.controllerService.operatorRecoveryOnly.enable;
  assert incomplete.config.aos.sandbox.resourceBank.policy == null;
  assert !incomplete.config.aos.sandbox.policyAuthority.enable;
    !recoveryAdmitted incomplete;

  forConfigurationModules = configurationModules: let
    # Start with an actual ordinary installation, not an option-presence stub.
    ordinary = mkSystem {
      systemName = "controller-recovery-ordinary";
      modules = [../../systems/server.nix] ++ configurationModules;
    };
    explicitlyOrdinary = ordinary.extendModules {
      modules = [
        ({lib, ...}: {
          aos.sandbox.controllerService.operatorRecoveryOnly.enable = lib.mkForce false;
        })
      ];
    };
    selected = ordinary.extendModules {
      modules = [
        ({lib, ...}: {
          aos.sandbox.controllerService = {
            enable = lib.mkOverride 60 true;
            publicApi.enable = lib.mkOverride 60 true;
            operatorRecoveryOnly.enable = lib.mkOverride 60 true;
            publisherIngress.enable = lib.mkOverride 60 false;
            sourceSuccessorIssuance.enable = lib.mkOverride 60 false;
            createQ04PolicySubgate.enable = lib.mkOverride 60 false;
            gitUploadBootstrap.enable = lib.mkOverride 60 false;
            gitReadInspection.enable = lib.mkOverride 60 false;
          };
          aos.sandbox.nixBroker.enable = lib.mkOverride 60 false;
        })
      ];
    };
    cfg = selected.config;
    sandbox = cfg.aos.sandbox;
    unit = cfg.systemd.services.aos-sandboxd.serviceConfig;
    normalUnit = ordinary.config.systemd.services.aos-sandboxd.serviceConfig;
    explicitNormalUnit = explicitlyOrdinary.config.systemd.services.aos-sandboxd.serviceConfig;
    normalProfile = sandbox.policyAuthority._normalStartupProfile;
    extend = module: selected.extendModules {modules = [module];};
    missingPolicy = extend ({lib, ...}: {
      aos.sandbox.resourceBank.policy = lib.mkForce null;
    });
    missingProfile = extend ({lib, ...}: {
      aos.sandbox.policyAuthority.enable = lib.mkForce false;
    });
    wrongPackage = extend ({lib, ...}: {
      aos.sandbox.controllerService.package = lib.mkForce pkgs.coreutils;
    });
    missingPublic = extend ({lib, ...}: {
      aos.sandbox.controllerService.publicApi.enable = lib.mkForce false;
    });
    conflicts = {
      publisher = extend ({lib, ...}: {
        aos.sandbox.controllerService.publisherIngress.enable = lib.mkForce true;
      });
      sourceIssuance = extend ({lib, ...}: {
        aos.sandbox.controllerService.sourceSuccessorIssuance.enable = lib.mkForce true;
      });
      createQ04 = extend ({lib, ...}: {
        aos.sandbox.controllerService.createQ04PolicySubgate.enable = lib.mkForce true;
      });
      gitUpload = extend ({lib, ...}: {
        aos.sandbox.controllerService.gitUploadBootstrap.enable = lib.mkForce true;
      });
      gitInspection = extend ({lib, ...}: {
        aos.sandbox.controllerService.gitReadInspection.enable = lib.mkForce true;
      });
      nix = extend ({lib, ...}: {
        aos.sandbox.nixBroker.enable = lib.mkForce true;
        # Isolate the actual purpose assertion without requesting a Nix package
        # from absent online-Nix installation inputs.
        aos.sandbox.controllerService.package = lib.mkForce pkgs.aos-sandboxd;
      });
    };
    negativeAssertions =
      {
        missingPolicy = !recoveryAdmitted missingPolicy;
        missingProfile = !recoveryAdmitted missingProfile;
        wrongPackage = !recoveryAdmitted wrongPackage;
        missingPublic = !recoveryAdmitted missingPublic;
      }
      // builtins.mapAttrs (_: system: !recoveryAdmitted system) conflicts;
    ordinaryFields = ["Type" "NotifyAccess" "TimeoutStartSec" "ExecStart" "ExecStartPre"];
    project = names: value: lib.genAttrs names (name: value.${name});
    validation = assert builtins.isList configurationModules && configurationModules != [];
    assert ordinary.config.aos.sandbox.controllerService.enable;
    assert !ordinary.config.aos.sandbox.controllerService.operatorRecoveryOnly.enable;
    assert sandbox.controllerService.enable && sandbox.controllerService.publicApi.enable;
    assert sandbox.controllerService.operatorRecoveryOnly.enable;
    assert sandbox.controllerService.package == pkgs.aos-sandboxd;
    assert sandbox.resourceBank.policy != null && sandbox.resourceBank._imagePolicy != null;
    assert sandbox.policyAuthority.enable && normalProfile != null;
    assert builtins.all (check: check.assertion) ordinary.config.assertions;
    assert builtins.all (check: check.assertion) cfg.assertions;
    assert recoveryAdmitted selected;
    assert unit.Type == "notify" && unit.NotifyAccess == "main";
    assert unit.TimeoutStartSec == "infinity";
    assert unit.ExecStartPre == [];
    assert lib.hasInfix " --public-api" unit.ExecStart;
    assert lib.hasInfix " --operator-recover-only" unit.ExecStart;
    assert builtins.elem "${normalProfile}/profile.json:aos-normal-root-client-profile:read-only" unit.OpenFile;
    assert project ordinaryFields normalUnit == project ordinaryFields explicitNormalUnit;
    assert normalUnit.Type == "notify" && normalUnit.TimeoutStartSec == "90s";
    assert !lib.hasInfix " --operator-recover-only" normalUnit.ExecStart;
    assert builtins.all (accepted: accepted) (builtins.attrValues negativeAssertions); true;
  in {
    inherit ordinary selected validation negativeAssertions;
    bootstrapImage = sandbox.resourceBank._imagePolicy;
    rootProfile = normalProfile;
    systemdUnits = "${cfg.system.build.managerConfiguration}/systemd-units";
  };
in {
  inherit incomplete incompleteAssertions forConfigurationModules;
  missingPositiveConfiguration = [
    "An actual ordinary Controller installation module set with complete resourceBank.policy"
    "Enabled real policyAuthority and its computed normal startup profile"
    "Existing independent broker, public TLS/registration and role credential names"
  ];
}
