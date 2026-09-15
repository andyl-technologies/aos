##! Fixed-point aggregation of neutral service facets into one systemd unit.
{
  lib,
  pkgs,
}: let
  abilitiesModule = ../../pkgs/system/_systemd-abilities.nix;
  providerModule = ../../pkgs/system/_systemd-provider.nix;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  artifact = lib.abilities.packageOutput {};
  artifactLocatorFor = selector:
    if (selector._type or null) != "aos-package-output-selector"
    then throw "provider attempted to resolve a materialized artifact reference"
    else {
      artifactReference = {
        _type = "aos-artifact-reference";
        content = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
        nar_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        closure = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
      };
      path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
    };
  requirement = selected: methods: {
    interface = selected.identity.name;
    inherit (selected.identity) abi descriptor;
    inherit methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  consumerModule = {
    config.aos.abilities = {
      instances.application = {};
      requirementTemplates = {
        lifecycle = requirement serviceManagement.interfaces.lifecycle ["observe" "start" "stop"];
        logging = requirement serviceManagement.interfaces.logging ["observe"];
        start-policy = requirement serviceManagement.interfaces.startPolicy ["observe"];
        watchdog = requirement serviceManagement.interfaces.watchdog ["observe"];
      };
      requests = {
        lifecycle = {
          requirement = "lifecycle";
          consumer = "application";
          scope = ["main"];
          parameters = {
            service = "main";
            enabled = true;
            description = "Example service";
            execution_model = "foreground";
            environment_files = [];
            condition = [];
            pre_start = [];
            start = [
              {
                executable = {
                  inherit artifact;
                  entry_point = "bin/example";
                  arguments = ["--serve"];
                };
                ignore_failure = false;
              }
            ];
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "on-failure";
            restart_delay_millis = 1000;
            remain_after_exit = false;
            start_timeout_millis = 30000;
            stop_timeout_millis = 30000;
          };
        };
        logging = {
          requirement = "logging";
          consumer = "application";
          scope = ["main"];
          parameters = {
            service = "main";
            enabled = true;
            standard_output = "structured";
            standard_error = "structured-and-console";
            directories = [];
            directory_mode = "0750";
          };
        };
        start-policy = {
          requirement = "start-policy";
          consumer = "application";
          scope = ["main"];
          parameters = {
            service = "main";
            enabled = true;
            accepted_exit_statuses = [0 2];
            restart_preventing_exit_statuses = [3];
            rate_interval_millis = 5000;
            rate_burst = 4;
          };
        };
        watchdog = {
          requirement = "watchdog";
          consumer = "application";
          scope = ["main"];
          parameters = {
            service = "main";
            enabled = true;
            timeout_millis = 10000;
            action = "stop";
          };
        };
      };
    };
  };
  evaluation = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      ../../modules/systemd/system.nix
      {
        config.aos.abilities = {
          environment = {
            authority = "test";
            key = "systemd-service";
            stage = "host";
          };
          bindings = {
            "test:lifecycle" = {
              request = "consumer:lifecycle";
              implementation = "systemd:service-lifecycle";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:logging" = {
              request = "consumer:logging";
              implementation = "systemd:service-logging";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:start-policy" = {
              request = "consumer:start-policy";
              implementation = "systemd:service-start-policy";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:watchdog" = {
              request = "consumer:watchdog";
              implementation = "systemd:service-watchdog";
              providerInstance = "systemd:manager";
              slot = "main";
            };
          };
        };
      }
    ];
    packageModules = [
      {
        name = "systemd";
        module = {
          imports = [abilitiesModule providerModule];
          config.aos.abilities.instances.manager = {};
        };
      }
      {
        name = "consumer";
        module = consumerModule;
      }
    ];
    specialArgs = {
      inherit artifactLocatorFor pkgs;
      packageName = "systemd";
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  resources = builtins.attrValues evaluation.config.aos.abilities.desiredResources;
  resource = builtins.head resources;
  unitName = resource.realization.systemd_unit.unit_name;
  primary = builtins.head resource.realization.units;
  section = name:
    builtins.head (builtins.filter (candidate: candidate.name == name) primary.sections);
  directives = name: selected:
    builtins.filter (directive: directive.name == name) selected.directives;
  unitSection = section "Unit";
  serviceSection = section "Service";
  execStart = builtins.head (directives "ExecStart" serviceSection);
  execStartSubstitutions = builtins.attrValues execStart.value.substitutions;
  executable = builtins.head (builtins.filter
    (substitution: substitution.source.kind == "artifact-path")
    execStartSubstitutions);
  templates = name: selected:
    builtins.map (directive: directive.value.template) (directives name selected);
  serviceRenderer = import ../../pkgs/system/_systemd-service-document.nix {
    inherit lib;
    serviceFacets = resource.realization.facets;
    unitNameForReference = _: throw "ownership fixture has no dependencies";
  };
  ownershipResource = owner: resource // {
    value = resource.value // {
      identity = {
        principal = "example";
        primary_group = "example";
        supplementary_groups = [];
        ephemeral = false;
        file_creation_mask = "0022";
      };
      directories.managed = [
        {
          purpose = "state";
          path = "example/nested";
          mode = "0750";
          retention = "persistent";
          inherit owner;
          group = "example";
        }
      ];
    };
  };
  matchedOwnership = serviceRenderer.realizationFor serviceManagement.interfaces.lifecycle.identity (
    ownershipResource "example"
  );
  mismatchedOwnership = builtins.tryEval (builtins.deepSeq (
      serviceRenderer.realizationFor serviceManagement.interfaces.lifecycle.identity (
        ownershipResource "another-principal"
      )
    )
    true);
in
  assert builtins.length resources == 1;
  assert resource.kind == "aos.service.instance";
  assert resource.controller == "test:lifecycle";
  assert resource.value.lifecycle.description == "Example service";
  assert resource.value.logging.standard_output == "structured";
  assert resource.realization.schema == "aos.systemd.service-realization/v2";
  assert primary.systemd_unit.unit_name == unitName;
  assert builtins.length (directives "StartLimitIntervalSec" unitSection) == 1;
  assert builtins.length (directives "StartLimitBurst" unitSection) == 1;
  assert templates "StandardOutput" serviceSection == ["journal"];
  assert templates "StandardError" serviceSection == ["journal+console"];
  assert templates "RestartPreventExitStatus" serviceSection == ["3" "SIGABRT"];
  assert executable.source.artifact == artifact;
  assert executable.source.relative_path == "bin/example";
  assert lib.hasInfix "@@AOS_SYSTEMD_SUBSTITUTION:" execStart.value.template;
  assert !lib.hasInfix "/nix/store/" (builtins.toJSON resource.realization);
  assert resource.realization.links == [
    {
      parent = {
        kind = "unit";
        unit_name = "multi-user.target";
      };
      child = resource.realization.systemd_unit;
      relationship = "wants";
    }
  ];
  assert builtins.length evaluation.config.systemd.providerUnitArtifacts == 1;
  assert builtins.length matchedOwnership.units == 1;
  assert !mismatchedOwnership.success; true
