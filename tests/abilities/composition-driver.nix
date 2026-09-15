##! Fixed-point composition across terminal and pure feature implementations.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  lifecycleDeclaration =
    interfaces.lifecycle.declaration
    // {
      outputs.marker = {
        description = "Marks completion of merged lifecycle composition.";
        schema = lib.abilities.types.boolean;
        phase = "planning";
        visibility = "protected";
        lifetime = "instance";
      };
    };
  lifecycleInterface =
    interfaces.lifecycle
    // {
      declaration = lifecycleDeclaration;
      identity = lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration lifecycleDeclaration
      );
    };
  lifecycleRequest = {
    service = "main";
    enabled = true;
    description = "Fixed-point composition fixture";
    execution_model = "foreground";
    working_directory = null;
    environment_files = [];
    condition = [];
    pre_start = [];
    start = [
      {
        executable = {
          artifact = lib.abilities.packageOutput {};
          entry_point = "bin/example";
          arguments = [];
        };
        ignore_failure = false;
      }
    ];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "on-failure";
    restart_delay_millis = 100;
    remain_after_exit = false;
    start_timeout_millis = 1000;
    stop_timeout_millis = 1000;
  };
  dependencyRequest = {
    service = "main";
    enabled = true;
    after = [];
    before = [];
    requires = [];
    wants = [];
  };
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
    conditionalRequirements = [];
  };
  provideFacet = facet: {requests, ...}:
    emptyProvision
    // {
      resourceFragments = builtins.listToAttrs (builtins.map (request: {
          name = request.parameters.service;
          value = {
            kind = interfaces.serviceInstance.identity.name;
            lifetime = "instance";
            value = {
              inherit (request.parameters) service enabled;
              ${facet} = builtins.removeAttrs request.parameters ["service" "enabled"];
            };
          };
        })
        (builtins.attrValues requests));
    };
  handlerArtifact = lib.abilities.packageOutput {};
  handler = interface: {
    artifact = handlerArtifact;
    entryPoint = "libexec/fixture-handler";
    arguments = interface.requestType;
    result = interface.observationType;
  };
  requirement = interface: methods: {
    description = "Selects ${interface.identity.name} for the composition fixture.";
    inherit (interface.identity) abi descriptor;
    interface = interface.identity.name;
    inherit methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  providerModule = {
    config.aos.abilities = {
      interfaces = {
        service-instance = interfaces.serviceInstance.declaration;
        service-lifecycle = lifecycleDeclaration;
        service-dependencies = interfaces.dependencies.declaration;
        network-readiness = interfaces.networkReadiness.declaration;
      };
      implementations = {
        service-lifecycle = {
          description = "Controls the composed fixture service.";
          interface = lifecycleInterface.alias;
          methods = lifecycleInterface.methods;
          guarantees = [];
          requirements.network = {
            alias = "network";
            accepted_interfaces = [interfaces.networkReadiness.identity];
            methods = ["observe"];
            guarantees = [];
            strength = "required";
            fallback = null;
          };
          artifact = handlerArtifact;
          handlerDescriptor = handler lifecycleInterface;
          desiredType = lib.abilities.types.record {
            fields.backend = lib.abilities.types.enum ["fixture"];
          };
          provide = provideFacet "lifecycle";
          compose = {
            requests,
            resources,
            ...
          }: {
            requests = {};
            outputs = builtins.mapAttrs (_: _: {marker = true;}) requests;
            conditionalRequirements = [];
            realizations = builtins.mapAttrs (_: _: {backend = "fixture";}) resources;
          };
        };
        service-dependencies = {
          description = "Contributes dependency facets to the fixture service.";
          interface = interfaces.dependencies.alias;
          methods = interfaces.dependencies.methods;
          guarantees = [];
          provide = provideFacet "dependencies";
        };
        network-readiness = {
          description = "Publishes one fixture network readiness reference.";
          interface = interfaces.networkReadiness.alias;
          methods = interfaces.networkReadiness.methods;
          guarantees = [];
          provide = {
            instance,
            requests,
            ...
          }:
            emptyProvision
            // {
              outputs =
                builtins.mapAttrs (_: _: {
                  readiness-resource = {
                    interface = interfaces.networkReadiness.identity;
                    resource = {
                      provider = instance.id;
                      key = "network-online";
                    };
                    operations = ["observe"];
                    lifetime = "instance";
                  };
                })
                requests;
            };
        };
      };
      instances.manager = {};
    };
  };
  consumerModule = {
    config.aos.abilities = {
      requirementTemplates = {
        lifecycle = requirement lifecycleInterface ["observe" "start" "stop"];
        dependencies = requirement interfaces.dependencies ["observe"];
        network = requirement interfaces.networkReadiness ["observe"];
      };
      instances.consumer = {};
      requests = {
        lifecycle = {
          requirement = "lifecycle";
          consumer = "consumer";
          scope = [];
          parameters = lifecycleRequest;
        };
        dependencies = {
          requirement = "dependencies";
          consumer = "consumer";
          scope = [];
          parameters = dependencyRequest;
        };
        network = {
          requirement = "network";
          consumer = "consumer";
          scope = [];
          parameters = {
            scope = "configured-connectivity";
            address_families = ["ipv4" "ipv6"];
          };
        };
      };
    };
  };
  baseBindings = {
    "test:lifecycle" = {
      request = "consumer:lifecycle";
      implementation = "provider:service-lifecycle";
      providerInstance = "provider:manager";
      slot = "main";
    };
    "test:dependencies" = {
      request = "consumer:dependencies";
      implementation = "provider:service-dependencies";
      providerInstance = "provider:manager";
      slot = "main";
    };
    "test:network" = {
      request = "consumer:network";
      implementation = "provider:network-readiness";
      providerInstance = "provider:manager";
      slot = "network-online";
    };
  };
  evaluate = {
    providerAdditions ? [],
    consumerAdditions ? [],
    bindings ? baseBindings,
  }:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "composition";
              stage = "host";
            };
            inherit bindings;
          };
        }
      ];
      packageModules = [
        {
          name = "provider";
          module = {imports = [providerModule] ++ providerAdditions;};
        }
        {
          name = "consumer";
          module = {imports = [consumerModule] ++ consumerAdditions;};
        }
      ];
    };
  evaluated = evaluate {};
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  networkOutput = abilities.compositionOutputs."consumer:network".readiness-resource;
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;

  duplicateDependency = evaluate {
    consumerAdditions = [
      {
        config.aos.abilities.requests.duplicate-dependencies = {
          requirement = "dependencies";
          consumer = "consumer";
          scope = [];
          parameters = dependencyRequest;
        };
      }
    ];
    bindings =
      baseBindings
      // {
        "test:duplicate-dependencies" = {
          request = "consumer:duplicate-dependencies";
          implementation = "provider:service-dependencies";
          providerInstance = "provider:manager";
          slot = "main";
        };
      };
  };
  secondLifecycle = {
    config.aos.abilities.implementations.second-lifecycle = {
      description = "Second lifecycle controller used to prove ambiguity rejection.";
      interface = lifecycleInterface.alias;
      methods = lifecycleInterface.methods;
      guarantees = [];
      provide = provideFacet "lifecycle";
      compose = _: throw "ambiguous controller must be rejected before composition";
      desiredType = lib.abilities.types.boolean;
    };
  };
  ambiguousController = evaluate {
    providerAdditions = [secondLifecycle];
    consumerAdditions = [
      {
        config.aos.abilities.requests.second-lifecycle = {
          requirement = "lifecycle";
          consumer = "consumer";
          scope = [];
          parameters = lifecycleRequest;
        };
      }
    ];
    bindings =
      baseBindings
      // {
        "test:second-lifecycle" = {
          request = "consumer:second-lifecycle";
          implementation = "provider:second-lifecycle";
          providerInstance = "provider:manager";
          slot = "main";
        };
      };
  };
  duplicateOutput = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle.provide = context:
          (provideFacet "lifecycle" context)
          // {
            outputs = builtins.mapAttrs (_: _: {marker = true;}) context.requests;
          };
      }
    ];
  };
  pendingChildRequest = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle.compose = context: {
          requests."provider:child" = {
            requirement = "consumer:dependencies";
            consumer = "consumer:consumer";
            scope = ["child"];
            parameters = dependencyRequest;
          };
          outputs = builtins.mapAttrs (_: _: {marker = true;}) context.requests;
          realizations = builtins.mapAttrs (_: _: {backend = "fixture";}) context.resources;
          conditionalRequirements = [];
        };
      }
    ];
  };
  duplicatePendingChildRequest = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle = {
          provide = context:
            (provideFacet "lifecycle" context)
            // {
              requests."provider:child" = {
                requirement = "consumer:dependencies";
                consumer = "consumer:consumer";
                scope = ["child"];
                parameters = dependencyRequest;
              };
            };
          compose = context: {
            requests."provider:child" = {
              requirement = "consumer:dependencies";
              consumer = "consumer:consumer";
              scope = ["child"];
              parameters = dependencyRequest;
            };
            outputs = builtins.mapAttrs (_: _: {marker = true;}) context.requests;
            realizations = builtins.mapAttrs (_: _: {backend = "fixture";}) context.resources;
            conditionalRequirements = [];
          };
        };
      }
    ];
  };
  pendingConditionalRequirement = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle.provide = context:
          (provideFacet "lifecycle" context)
          // {conditionalRequirements = ["network"];};
      }
    ];
  };
  duplicateConditionalRequirement = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle.provide = context:
          (provideFacet "lifecycle" context)
          // {conditionalRequirements = ["network" "network"];};
      }
    ];
  };
  pendingRequirement = builtins.head (
    builtins.attrValues pendingConditionalRequirement.config.aos.abilities.compositionPendingRequirements
  );
in
  assert builtins.length (builtins.attrNames abilities.desiredResources) == 1;
  assert desired.controller == "test:lifecycle";
  assert desired.kind == interfaces.serviceInstance.identity.name;
  assert desired.value.lifecycle == builtins.removeAttrs lifecycleRequest ["service" "enabled"];
  assert desired.value.dependencies == builtins.removeAttrs dependencyRequest ["service" "enabled"];
  assert desired.realization == {backend = "fixture";};
  assert networkOutput.phase == "planning";
  assert networkOutput.visibility == "protected";
  assert networkOutput.lifetime == "instance";
  assert networkOutput.value.resource.provider == abilities.instanceIdentities."provider:manager";
  assert networkOutput.value.resource.key == "network-online";
  assert abilities.compositionOutputs."consumer:lifecycle".marker.value;
  assert rejects duplicateDependency.config.aos.abilities.desiredResources;
  assert rejects ambiguousController.config.aos.abilities.desiredResources;
  assert rejects duplicateOutput.config.aos.abilities.desiredResources;
  assert builtins.attrNames pendingChildRequest.config.aos.abilities.compositionPendingRequests == ["provider:child"];
  assert rejects pendingChildRequest.config.aos.abilities.desiredResources;
  assert rejects duplicatePendingChildRequest.config.aos.abilities.compositionPendingRequests;
  assert pendingRequirement.implementation == "provider:service-lifecycle";
  assert pendingRequirement.providerInstance == "provider:manager";
  assert pendingRequirement.requirements == ["network"];
  assert rejects pendingConditionalRequirement.config.aos.abilities.desiredResources;
  assert rejects duplicateConditionalRequirement.config.aos.abilities.compositionPendingRequirements; true
