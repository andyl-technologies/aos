##! Fixed-point aggregation of neutral service facets into one systemd unit.
{
  lib,
  pkgs,
}: let
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "service-lifecycle";
  };
  providerRoot = selectedSystemdProvider.configRoot;
  serviceEffectsRequest = lib.abilities.compositionRequestKey {
    implementation = "systemd:service-lifecycle";
    providerInstance = "systemd:manager";
    key = "main";
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  artifact = lib.abilities.packageOutput {};
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
        manager-identity = requirement serviceManagement.interfaces.managerIdentity ["observe"];
        socket-activation = requirement serviceManagement.interfaces.socketActivation ["observe"];
        terminal = requirement serviceManagement.interfaces.terminal ["observe"];
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
        manager-identity = {
          requirement = "manager-identity";
          consumer = "application";
          scope = ["main"];
          parameters = {
            service = "main";
            enabled = true;
            name = "example";
            aliases = ["example-compat"];
          };
        };
        socket-activation = {
          requirement = "socket-activation";
          consumer = "application";
          scope = ["main"];
          parameters = {
            service = "main";
            enabled = true;
            sockets = [
              {
                name = "api";
                manager_name = "example-api";
                enabled = true;
                endpoints = [
                  {
                    kind = "unix";
                    path = "/run/example/api.sock";
                  }
                ];
                mode = "0660";
                group = "operators";
                remove_on_stop = true;
                prerequisites = [];
              }
              {
                name = "api-admin";
                manager_name = "example-api-admin";
                enabled = true;
                endpoints = [
                  {
                    kind = "unix";
                    path = "/run/example/api-admin.sock";
                  }
                ];
                mode = "0600";
                remove_on_stop = true;
                prerequisites = [];
                after = ["api"];
                binds_to = ["api"];
              }
            ];
            service_dependencies = {
              after = ["api" "api-admin"];
              binds_to = ["api"];
              requires = [];
              wants = ["api-admin"];
            };
          };
        };
        terminal = {
          requirement = "terminal";
          consumer = "application";
          scope = ["main"];
          parameters = {
            service = "main";
            enabled = true;
            device = "/dev/tty1";
            reset = true;
            hangup = true;
            deallocate = true;
            send_hangup_on_stop = true;
            start_when_idle = true;
            session_identifier = "tty1";
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
          instances."systemd:manager" = {};
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
            "test:manager-identity" = {
              request = "consumer:manager-identity";
              implementation = "systemd:service-manager-identity";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:socket-activation" = {
              request = "consumer:socket-activation";
              implementation = "systemd:service-socket-activation";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:terminal" = {
              request = "consumer:terminal";
              implementation = "systemd:service-terminal";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:service-effects" = {
              request = serviceEffectsRequest;
              implementation = "systemd:systemd-service-effects";
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
        inherit (pkgs.systemd) version;
        module = pkgs.systemd.module + "/module.nix";
      }
      {
        name = "consumer";
        module = consumerModule;
      }
    ];
    selectedProviderModules = [
      selectedSystemdProvider
    ];
    specialArgs = {
      inherit pkgs;
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  resources = builtins.attrValues evaluation.config.aos.abilities.desiredResources;
  resource = builtins.head resources;
  unitName = resource.realization.systemd_unit.unit_name;
  primary = builtins.head (builtins.filter
    (unit: unit.systemd_unit.unit_name == unitName)
    resource.realization.units);
  socketUnit = builtins.head (builtins.filter
    (unit: unit.systemd_unit.unit_name == "example-api.socket")
    resource.realization.units);
  adminSocketUnit = builtins.head (builtins.filter
    (unit: unit.systemd_unit.unit_name == "example-api-admin.socket")
    resource.realization.units);
  sectionFor = unit: name:
    builtins.head (builtins.filter (candidate: candidate.name == name) unit.sections);
  section = sectionFor primary;
  directives = name: selected:
    builtins.filter (directive: directive.name == name) selected.directives;
  unitSection = section "Unit";
  serviceSection = section "Service";
  socketSection = sectionFor socketUnit "Socket";
  adminSocketUnitSection = sectionFor adminSocketUnit "Unit";
  execStart = builtins.head (directives "ExecStart" serviceSection);
  execStartSubstitutions = builtins.attrValues execStart.value.substitutions;
  executable = builtins.head (builtins.filter
    (substitution: substitution.source.kind == "artifact-path")
    execStartSubstitutions);
  templates = name: selected:
    builtins.map (directive: directive.value.template) (directives name selected);
  unitIdentities = name: selected:
    builtins.map
    (directive:
      (builtins.head (builtins.attrValues directive.value.substitutions)).source.identity)
    (directives name selected);
  guarantees = evaluation.config.aos.abilities.guarantees;
  lifecycleImplementation = evaluation.config.aos.abilities.implementations."systemd:service-lifecycle";
  ownershipResource = owner:
    resource
    // {
      value =
        resource.value
        // {
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
  ownershipComposition = owner:
    lifecycleImplementation.compose {
      bindings.lifecycle.providerInstance = "systemd:manager";
      resources.main = ownershipResource owner;
    };
  matchedOwnership = ownershipComposition "example";
  mismatchedOwnership = ownershipComposition "another-principal";
  ownershipPreparation = builtins.head (builtins.filter
    (request: request.requirement == "directory-preparation")
    (builtins.attrValues mismatchedOwnership.requests));
  ownershipPreparationRequest = lib.abilities.compositionRequestKey {
    implementation = "systemd:service-lifecycle";
    providerInstance = "systemd:manager";
    key = ownershipPreparation.parameters.name;
  };
  effectsRequest = evaluation.config.aos.abilities.compositionRequests.${serviceEffectsRequest};
  conditionImplementation = evaluation.config.aos.abilities.implementations."systemd:service-conditions";
  rejectedProviderSelection = selectedProvider:
    builtins.tryEval (builtins.deepSeq ((lib.evalModules {
        inherit lib pkgs;
        modules = [lib.abilities.module];
        selectedProviderModules = [selectedProvider];
      }).config.aos.abilities.implementations)
      true);
  traversalSelection = rejectedProviderSelection (
    selectedSystemdProvider
    // {module = "${providerRoot}/share/aos/providers/../providers/systemd.nix";}
  );
  mismatchedRootSelection = rejectedProviderSelection (
    selectedSystemdProvider
    // {configRoot = "${providerRoot}/share/aos";}
  );
in
  assert builtins.length resources == 1;
  assert resource.kind == "aos.service.instance";
  assert resource.controller == "test:lifecycle";
  assert resource.value.lifecycle.description == "Example service";
  assert resource.value.logging.standard_output == "structured";
  assert resource.realization.schema == "aos.systemd.service-realization/v1";
  assert primary.systemd_unit.unit_name == unitName;
  assert unitName == "example.service";
  assert builtins.length (directives "StartLimitIntervalSec" unitSection) == 1;
  assert builtins.length (directives "StartLimitBurst" unitSection) == 1;
  assert templates "StandardOutput" serviceSection == ["journal"];
  assert templates "StandardError" serviceSection == ["journal+console"];
  assert templates "RestartPreventExitStatus" serviceSection == ["3" "SIGABRT"];
  assert templates "Type" serviceSection == ["idle"];
  assert builtins.length (templates "TTYPath" serviceSection) == 1;
  assert lib.hasInfix "@@AOS_SYSTEMD_SUBSTITUTION:" (builtins.head (templates "TTYPath" serviceSection));
  assert templates "TTYReset" serviceSection == ["yes"];
  assert templates "TTYVHangup" serviceSection == ["yes"];
  assert templates "TTYVTDisallocate" serviceSection == ["yes"];
  assert templates "SendSIGHUP" serviceSection == ["yes"];
  assert templates "UtmpIdentifier" serviceSection == ["tty1"];
  assert executable.source.artifact == artifact // {package = "consumer";};
  assert executable.source.relative_path == "bin/example";
  assert lib.hasInfix "@@AOS_SYSTEMD_SUBSTITUTION:" execStart.value.template;
  assert !lib.hasInfix "/nix/store/" (builtins.toJSON resource.realization);
  assert unitIdentities "After" unitSection
  == [
    {
      kind = "unit";
      unit_name = "example-api.socket";
    }
    {
      kind = "unit";
      unit_name = "example-api-admin.socket";
    }
  ];
  assert unitIdentities "BindsTo" unitSection
  == [
    {
      kind = "unit";
      unit_name = "example-api.socket";
    }
  ];
  assert unitIdentities "Wants" unitSection
  == [
    {
      kind = "unit";
      unit_name = "example-api-admin.socket";
    }
  ];
  assert unitIdentities "After" adminSocketUnitSection
  == [
    {
      kind = "unit";
      unit_name = "example-api.socket";
    }
  ];
  assert unitIdentities "BindsTo" adminSocketUnitSection
  == [
    {
      kind = "unit";
      unit_name = "example-api.socket";
    }
  ];
  assert resource.realization.links
  == [
    {
      parent = {
        kind = "unit";
        unit_name = "sockets.target";
      };
      child = {
        kind = "unit";
        unit_name = "example-api-admin.socket";
      };
      relationship = "wants";
    }
    {
      parent = {
        kind = "unit";
        unit_name = "sockets.target";
      };
      child = {
        kind = "unit";
        unit_name = "example-api.socket";
      };
      relationship = "wants";
    }
    {
      parent = {
        kind = "unit";
        unit_name = "multi-user.target";
      };
      child = resource.realization.systemd_unit;
      relationship = "wants";
    }
  ];
  assert resource.realization.aliases
  == [
    {
      alias = {
        kind = "unit";
        unit_name = "example-compat.service";
      };
      target = resource.realization.systemd_unit;
    }
  ];
  assert templates "SocketMode" socketSection == ["0660"];
  assert templates "SocketGroup" socketSection != [];
  assert templates "RemoveOnStop" socketSection == ["yes"];
  assert builtins.length evaluation.config.systemd.providerUnitArtifacts == 1;
  assert guarantees."core:service-template-exact-reuse".name == "aos.guarantee.service-template-exact-reuse";
  assert lifecycleImplementation.guarantees == ["core:service-template-exact-reuse"];
  assert lifecycleImplementation.handlerDescriptor == null;
  assert builtins.isFunction lifecycleImplementation.transition;
  assert lifecycleImplementation.requirements.directory-preparation.strength == "required";
  assert builtins.length matchedOwnership.realizations.main.units == 3;
  assert ownershipPreparation
  == {
    requirement = "directory-preparation";
    scope = ["managed-directory"];
    slot = ownershipPreparation.parameters.name;
    parameters = {
      name = ownershipPreparation.parameters.name;
      entry.kind = "directory";
      destination = "/var/lib/example/nested";
      mode = "0750";
      owner = "another-principal";
      group = "example";
      prerequisites = [];
    };
  };
  assert !builtins.hasAttr ownershipPreparationRequest evaluation.config.aos.abilities.compositionOutputs;
  assert effectsRequest.parameters.kind == "service";
  assert effectsRequest.parameters.desired.service == "main";
  assert conditionImplementation.guarantees
  == [
    "core:service-condition-kernel-argument"
    "core:service-condition-path"
  ];
  assert !traversalSelection.success;
  assert !mismatchedRootSelection.success; true
