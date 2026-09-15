##! Fixed-point composition across terminal and pure feature implementations.
args @ {lib, ...}: let
  returnPending = args.returnPending or false;
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
      outputs.runtime-marker = {
        description = "Proves pure composition cannot manufacture runtime evidence.";
        schema = lib.abilities.types.boolean;
        phase = "runtime";
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
          artifact = handlerArtifact;
          handlerDescriptor = handler interfaces.networkReadiness;
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
    roundAdditions ? [],
    bindings ? baseBindings,
  }:
    lib.evalModules {
      inherit lib;
      modules =
        [
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
        ]
        ++ roundAdditions;
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
  resolved = builtins.attrValues abilities.resolvedResources;
  controlledResource = builtins.head (builtins.filter (resource: resource.controller != null) resolved);
  publishedResource = builtins.head (builtins.filter (resource: resource.controller == null) resolved);
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
  childRequirementKey = lib.abilities.compositionRequirementKey {
    implementation = "provider:service-lifecycle";
    alias = "network";
  };
  childRequestKey = lib.abilities.compositionRequestKey {
    implementation = "provider:service-lifecycle";
    providerInstance = "provider:manager";
    key = "child";
  };
  childParameters = {
    scope = "configured-connectivity";
    address_families = ["ipv4"];
  };
  childRequest = {
    requirement = "network";
    scope = ["child"];
    parameters = childParameters;
  };
  lifecycleWithChild = {
    config.aos.abilities.implementations.service-lifecycle.provide = context:
      (provideFacet "lifecycle" context)
      // {
        requests.child = childRequest;
      };
  };
  changedPublishedOperations = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.network-readiness.provide = {
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
                  operations = [];
                  lifetime = "instance";
                };
              })
              requests;
          };
      }
    ];
  };
  changedObserverHandler = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.network-readiness.handlerDescriptor =
          (handler interfaces.networkReadiness)
          // {entryPoint = "libexec/changed-fixture-handler";};
      }
    ];
  };
  publishedRevision = evaluation: let
    resources = builtins.attrValues evaluation.config.aos.abilities.resolvedResources;
  in
    (builtins.head (builtins.filter (resource: resource.controller == null) resources)).revision;
  pendingChildRequest = evaluate {
    providerAdditions = [lifecycleWithChild];
  };
  duplicatePendingChildRequest = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle = {
          provide = context:
            (provideFacet "lifecycle" context)
            // {
              requests.child = childRequest;
            };
          compose = context: {
            requests.child = childRequest;
            outputs = builtins.mapAttrs (_: _: {marker = true;}) context.requests;
            realizations = builtins.mapAttrs (_: _: {backend = "fixture";}) context.resources;
          };
        };
      }
    ];
  };
  authoredConditionalRequirement = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle.provide = context:
          (provideFacet "lifecycle" context)
          // {conditionalRequirements = ["network"];};
      }
    ];
  };
  resolvedChild = evaluate {
    providerAdditions = [
      lifecycleWithChild
      {
        config.aos.abilities.implementations.service-lifecycle.compose = context: {
          requests = {};
          outputs = assert context.children.child.request == childRequestKey;
          assert context.children.child.binding == "test:child-network";
          assert context.children.child.outputs.readiness-resource.phase == "planning";
            builtins.mapAttrs (_: _: {marker = true;}) context.requests;
          realizations = builtins.mapAttrs (_: _: {backend = "fixture";}) context.resources;
        };
      }
    ];
    bindings =
      baseBindings
      // {
        "test:child-network" = {
          request = childRequestKey;
          implementation = "provider:network-readiness";
          providerInstance = "provider:manager";
          slot = "network-child";
        };
      };
  };
  collidingAuthoredChild = evaluate {
    providerAdditions = [lifecycleWithChild];
    roundAdditions = [
      {
        config.aos.abilities.requests.${childRequestKey} = {
          requirement = "consumer:lifecycle";
          consumer = "consumer:consumer";
          scope = [];
          parameters = lifecycleRequest;
        };
      }
    ];
  };
  forgedAuthoredChild = evaluate {
    roundAdditions = [
      {
        config.aos.abilities.requests.${childRequestKey} = {
          requirement = childRequirementKey;
          consumer = "provider:manager";
          scope = ["child"];
          parameters = childParameters;
        };
      }
    ];
  };
  orphanChildBinding = evaluate {
    bindings =
      baseBindings
      // {
        "test:child-network" = {
          request = childRequestKey;
          implementation = "provider:network-readiness";
          providerInstance = "provider:manager";
          slot = "network-child";
        };
      };
  };
  mismatchedChildBinding = evaluate {
    providerAdditions = [
      lifecycleWithChild
      {
        config.aos.abilities.implementations.network-incomplete = {
          description = "Omits the observe method required by the child request.";
          interface = interfaces.networkReadiness.alias;
          methods = [];
          guarantees = [];
          provide = providerModule.config.aos.abilities.implementations.network-readiness.provide;
        };
      }
    ];
    bindings =
      baseBindings
      // {
        "test:child-network" = {
          request = childRequestKey;
          implementation = "provider:network-incomplete";
          providerInstance = "provider:manager";
          slot = "network-child";
        };
      };
  };
  multiplyBoundChild = evaluate {
    providerAdditions = [lifecycleWithChild];
    bindings =
      baseBindings
      // {
        "test:child-network" = {
          request = childRequestKey;
          implementation = "provider:network-readiness";
          providerInstance = "provider:manager";
          slot = "network-child";
        };
        "test:duplicate-child-network" = {
          request = childRequestKey;
          implementation = "provider:network-readiness";
          providerInstance = "provider:manager";
          slot = "network-child-duplicate";
        };
      };
  };
  runtimeOutput = evaluate {
    providerAdditions = [
      {
        config.aos.abilities.implementations.service-lifecycle.compose = context: {
          requests = {};
          outputs =
            builtins.mapAttrs (_: _: {
              marker = true;
              runtime-marker = true;
            })
            context.requests;
          realizations = builtins.mapAttrs (_: _: {backend = "fixture";}) context.resources;
        };
      }
    ];
  };
  pendingRequirement = builtins.head (
    builtins.attrValues pendingChildRequest.config.aos.abilities.compositionPendingRequirements
  );
  pendingRequest = pendingChildRequest.config.aos.abilities.compositionPendingRequests.${childRequestKey};
in
  if returnPending
  then {requests = pendingChildRequest.config.aos.abilities.compositionPendingRequests;}
  else
    assert builtins.length (builtins.attrNames abilities.desiredResources) == 1;
    assert desired.controller == "test:lifecycle";
    assert desired.kind == interfaces.serviceInstance.identity.name;
    assert desired.value.lifecycle == builtins.removeAttrs lifecycleRequest ["service" "enabled"];
    assert desired.value.dependencies == builtins.removeAttrs dependencyRequest ["service" "enabled"];
    assert desired.realization == {backend = "fixture";};
    assert builtins.length resolved == 2;
    assert controlledResource.controller == "test:lifecycle";
    assert publishedResource.controller == null;
    assert publishedResource.kind == interfaces.networkReadiness.identity.name;
    assert publishedResource.value == networkOutput.value;
    assert publishedResource.realization == null;
    assert publishedRevision evaluated != publishedRevision changedPublishedOperations;
    assert publishedRevision evaluated != publishedRevision changedObserverHandler;
    assert networkOutput.phase == "planning";
    assert networkOutput.visibility == "protected";
    assert networkOutput.lifetime == "instance";
    assert networkOutput.value.resource.provider == abilities.instanceIdentities."provider:manager";
    assert networkOutput.value.resource.key == "network-online";
    assert abilities.compositionOutputs."consumer:lifecycle".marker.value;
    assert rejects duplicateDependency.config.aos.abilities.desiredResources;
    assert rejects ambiguousController.config.aos.abilities.desiredResources;
    assert rejects duplicateOutput.config.aos.abilities.desiredResources;
    assert builtins.attrNames pendingChildRequest.config.aos.abilities.compositionPendingRequests == [childRequestKey];
    assert pendingRequest.localRequestKey == "child";
    assert pendingRequest.implementation == "provider:service-lifecycle";
    assert pendingRequest.providerInstance == "provider:manager";
    assert pendingRequest.requirement == "network";
    assert pendingRequest.declaration.requirement == childRequirementKey;
    assert lib.abilities.types.declarationKey.check childRequirementKey;
    assert lib.abilities.types.declarationKey.check childRequestKey;
    assert childRequirementKey
    == lib.abilities.compositionRequirementKey {
      implementation = "provider:service-lifecycle";
      alias = "network";
    };
    assert childRequestKey
    == lib.abilities.compositionRequestKey {
      implementation = "provider:service-lifecycle";
      providerInstance = "provider:manager";
      key = "child";
    };
    assert childRequestKey
    != lib.abilities.compositionRequestKey {
      implementation = "provider:service-lifecycle";
      providerInstance = "provider:alternate-manager";
      key = "child";
    };
    assert rejects pendingChildRequest.config.aos.abilities.desiredResources;
    assert rejects duplicatePendingChildRequest.config.aos.abilities.compositionPendingRequests;
    assert pendingRequirement.implementation == "provider:service-lifecycle";
    assert pendingRequirement.providerInstance == "provider:manager";
    assert pendingRequirement.requirements == ["network"];
    assert resolvedChild.config.aos.abilities.compositionPendingRequests == {};
    assert resolvedChild.config.aos.abilities.compositionRequests.${childRequestKey}.parameters == childParameters;
    assert builtins.length (builtins.attrNames resolvedChild.config.aos.abilities.desiredResources) == 1;
    assert rejects authoredConditionalRequirement.config.aos.abilities.compositionPendingRequirements;
    assert rejects collidingAuthoredChild.config.aos.abilities.desiredResources;
    assert rejects forgedAuthoredChild.config.aos.abilities.requests;
    assert rejects orphanChildBinding.config.aos.abilities.desiredResources;
    assert rejects mismatchedChildBinding.config.aos.abilities.desiredResources;
    assert rejects multiplyBoundChild.config.aos.abilities.desiredResources;
    assert rejects runtimeOutput.config.aos.abilities.compositionOutputs; true
