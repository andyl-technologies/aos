##! AOS pure-controller to package-owned terminal-handler contract.
{
  lib,
  pkgs,
}: let
  selectedConfigurationProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos;
    implementation = "configuration-materialization";
  };
  evaluation = lib.evalModules {
    inherit lib pkgs;
    modules = [
      lib.abilities.module
      {
        config.aos.abilities.environment = {
          authority = "test";
          key = "aos-controller-terminal";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "aos";
        version = pkgs.aos.version;
        module = pkgs.aos.module + "/module.nix";
      }
    ];
    selectedProviderModules = [selectedConfigurationProvider];
  };
  abilities = evaluation.config.aos.abilities;
  implementation = abilities.implementations."aos:configuration-materialization";
  requestName = "consumer:configuration";
  request = {
    consumer = "consumer:service";
    requirement = "consumer:configuration";
    scope = ["service"];
    parameters = {
      name = "demo";
      source = {
        kind = "inline-text";
        content = "enabled=true";
      };
      mode = "0644";
    };
  };
  incomingBinding = {
    request = requestName;
    implementation = "aos:configuration-materialization";
    providerInstance = "aos:configuration-materialization";
    slot = "demo";
  };
  provision = implementation.provide {
    requests.${requestName} = request;
    bindings.selected = incomingBinding;
  };
  provider = abilities.instanceIdentities."aos:configuration-materialization";
  resource =
    provision.resourceFragments.demo
    // {
      resource = {
        inherit provider;
        key = "demo";
      };
    };
  composition = implementation.compose {resources.demo = resource;};
  revision =
    resource
    // {
      realization = composition.realizations.demo;
      revision = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    };
  terminalInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration
    abilities.interfaces."aos:configuration-materialization-terminal"
  );
  resourceInterface = lib.abilities.interfaces.serviceManagement.interfaces.managedConfiguration.identity;
  controller = {
    inherit provider;
    group = "configuration-materialization";
  };
  authorizedBinding = {
    binding = {
      id = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      request = {
        consumer = provider;
        scope = ["service" "terminal"];
        key = "terminal-demo";
      };
      interface = terminalInterface;
      caller_grant = {
        methods = ["materialize" "observe" "release"];
        contributions = [];
      };
    };
  };
  transitionContext = {
    inherit provider;
    operation_scope = ["activation"];
    before = null;
    after.resources = [revision];
    changes = [
      {
        kind = "create";
        inherit (resource) resource;
        desired = revision;
        current = null;
      }
    ];
    controllers = [
      {
        inherit (resource) resource;
        inherit controller;
      }
    ];
    authorized_bindings = [authorizedBinding];
  };
  transition = implementation.transition transitionContext;
  operation = builtins.head transition.operations;
  signedProviders = pkgs.aos.contract.value.implementation.providers;
  hasExactlyOneExecutor = provider:
    (provider ? provider_module) != (provider ? handler);
  wrongTerminalBinding = builtins.tryEval (builtins.deepSeq (
      implementation.transition (
        transitionContext
        // {
          authorized_bindings = [
            (authorizedBinding
              // {
                binding = authorizedBinding.binding // {interface = resourceInterface;};
              })
          ];
        }
      )
    )
    true);
  rolloutImplementation = abilities.implementations."aos:image-rollout-effects";
  rolloutTerminalImplementation = abilities.implementations."aos:image-rollout-terminal";
  rolloutRequestName = "consumer:rollout";
  rolloutParameters = {
    candidate = {
      executor = "/nix/store/00000000000000000000000000000000-candidate-executor";
      state-format = "aos.test/v1";
      toplevel = "/nix/store/00000000000000000000000000000000-candidate";
      uki = "/nix/store/00000000000000000000000000000000-candidate-uki";
    };
    predecessor = {
      executor = "/nix/store/11111111111111111111111111111111-predecessor-executor";
      state-format = "aos.test/v1";
      toplevel = "/nix/store/11111111111111111111111111111111-predecessor";
      uki = "/nix/store/11111111111111111111111111111111-predecessor-uki";
    };
    concurrency = 1;
    retention-expires-at-millis = 1000000;
    strategy = "single-host-ab-v1";
  };
  rolloutProvision = rolloutImplementation.provide {
    requests.${rolloutRequestName} = {
      consumer = "consumer:release";
      requirement = "consumer:rollout";
      scope = ["release"];
      parameters = rolloutParameters;
    };
    bindings.selected = {
      request = rolloutRequestName;
      implementation = "aos:image-rollout-effects";
      providerInstance = "aos:image-rollout-effects";
      slot = "machine";
    };
  };
  rolloutProvider = abilities.instanceIdentities."aos:image-rollout-effects";
  rolloutResource =
    rolloutProvision.resourceFragments.machine
    // {
      resource = {
        provider = rolloutProvider;
        key = "machine";
      };
    };
  rolloutComposition = rolloutImplementation.compose {resources.machine = rolloutResource;};
  rolloutRevision =
    rolloutResource
    // {
      realization = rolloutComposition.realizations.machine;
      revision = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    };
  rolloutTerminalInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration
    abilities.interfaces."aos:image-rollout-terminal"
  );
  rolloutResourceInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration
    abilities.interfaces."aos:image-rollout-effects"
  );
  rolloutController = {
    provider = rolloutProvider;
    group = "rollout-effects";
  };
  rolloutBinding = {
    binding = {
      id = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
      request = {
        consumer = rolloutProvider;
        scope = ["release" "terminal"];
        key = "terminal-machine";
      };
      interface = rolloutTerminalInterface;
      caller_grant = {
        methods = [
          "drain"
          "hold"
          "observe-boot"
          "observe-health"
          "prepare"
          "retain"
          "retire"
          "select"
          "withdraw"
        ];
        contributions = [];
      };
    };
  };
  rolloutContext = {
    provider = rolloutProvider;
    operation_scope = ["activation"];
    before = null;
    after.resources = [rolloutRevision];
    changes = [
      {
        kind = "create";
        inherit (rolloutResource) resource;
        desired = rolloutRevision;
        current = null;
      }
    ];
    controllers = [
      {
        inherit (rolloutResource) resource;
        controller = rolloutController;
      }
    ];
    authorized_bindings = [rolloutBinding];
  };
  rolloutTransition = rolloutImplementation.transition rolloutContext;
  rolloutObserve = builtins.head (builtins.filter (operation:
    operation.key.key == "observe-health")
  rolloutTransition.operations);
  retirementTransition = rolloutImplementation.transition (
    rolloutContext
    // {
      before.resources = [rolloutRevision];
      after.resources = [];
      changes = [
        {
          kind = "remove";
          inherit (rolloutResource) resource;
          desired = null;
          current = rolloutRevision;
        }
      ];
    }
  );
in
  assert builtins.attrNames provision.requests == ["terminal-demo"];
  assert provision.requests."terminal-demo".requirement == "terminal";
  assert provision.requests."terminal-demo".parameters == request.parameters;
  assert provision.resourceFragments.demo.kind == resourceInterface.name;
  assert operation.interface == terminalInterface;
  assert operation.target.interface == resourceInterface;
  assert operation.target.resource == resource.resource;
  assert operation.method == "materialize";
  assert operation.recovery.reconcile.interface == terminalInterface;
  assert operation.recovery.cancel.interface == terminalInterface;
  assert !wrongTerminalBinding.success;
  assert builtins.all hasExactlyOneExecutor signedProviders;
  assert builtins.attrNames rolloutProvision.requests == ["terminal-machine"];
  assert rolloutTerminalImplementation.handlerDescriptor.entryPoint
  == "libexec/aos-image-rollout-provider";
  assert builtins.length rolloutTransition.decisions == 1;
  assert builtins.length rolloutTransition.merges == 1;
  assert builtins.all (operation:
    operation.interface
    == rolloutTerminalInterface
    && operation.target.interface == rolloutResourceInterface)
  rolloutTransition.operations;
  assert (builtins.head rolloutObserve.accesses).mode == "read";
  assert builtins.map (operation: operation.method) retirementTransition.operations
  == ["retire" "observe-health"]; true
