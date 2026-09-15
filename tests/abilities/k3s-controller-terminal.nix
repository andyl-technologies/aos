##! Verifies the K3s controllers delegate through one exact terminal binding.
{
  lib,
  pkgs,
}: let
  objectContract = lib.abilities.interfaces.kubernetesObjectManagement;
  configurationContract = import ../../pkgs/kubernetes/_k3s-config/configuration-interface.nix {inherit lib;};

  evaluateController = {
    requestKey,
    requestInterface,
    requestMethods,
    parameters,
    controllerAlias,
    controllerInstance,
    terminalAlias,
    providerModule,
    slot,
  }: let
    childRequestKey = lib.abilities.compositionRequestKey {
      implementation = "k3s-combined:${controllerAlias}";
      providerInstance = "k3s-combined:${controllerInstance}";
      key = slot;
    };
    evaluated = lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          aos.abilities = {
            environment = {
              authority = "test";
              key = "k3s-controller-terminal";
              stage = "host";
            };
            bindings."test:controller" = {
              request = "consumer:${requestKey}";
              implementation = "k3s-combined:${controllerAlias}";
              providerInstance = "k3s-combined:${controllerInstance}";
              inherit slot;
            };
            bindings."test:terminal" = {
              request = childRequestKey;
              implementation = "k3s-combined:${terminalAlias}";
              providerInstance = "k3s-combined:${controllerInstance}";
              inherit slot;
            };
          };
        }
      ];
      packageModules = [
        {
          name = "k3s-combined";
          version = pkgs.k3s-combined.version;
          module.imports = [
            ../../pkgs/kubernetes/_k3s-config/module.nix
            providerModule
            {config.aos.abilities.instances.${controllerInstance} = {};}
          ];
        }
        {
          name = "consumer";
          version = "1";
          module = {
            config.aos.abilities = lib.mkMerge [
              (lib.abilities.interfaces.serviceManagement.forProducer {
                consumerInstance = "workload";
                key = requestKey;
                interface = {
                  alias = requestInterface.alias;
                  declaration = requestInterface.declaration;
                };
                methods = requestMethods;
                inherit parameters;
              })
              {instances.workload = {};}
            ];
          };
        }
      ];
    };
  in {
    inherit childRequestKey;
    abilities = evaluated.config.aos.abilities;
  };

  object = evaluateController {
    requestKey = "objects";
    requestInterface = objectContract.controller;
    requestMethods = objectContract.controller.methods;
    parameters = {
      cluster.prerequisites = [];
      contributions = {};
    };
    controllerAlias = objectContract.controller.alias;
    controllerInstance = "object-controller";
    terminalAlias = "kubernetes-object-effects";
    providerModule = ../../pkgs/kubernetes/_k3s-config/object-provider.nix;
    slot = "objects";
  };
  configuration = evaluateController {
    requestKey = "configuration";
    requestInterface = configurationContract.controller;
    requestMethods = configurationContract.controller.methods;
    parameters = {
      base = {
        flannel_backend = "vxlan";
        disable_network_policy = false;
        disable_kube_proxy = false;
        node_labels = {};
        prerequisites = [];
      };
      contributions = {};
    };
    controllerAlias = configurationContract.controller.alias;
    controllerInstance = "configuration-controller";
    terminalAlias = "k3s-configuration-effects";
    providerModule = ../../pkgs/kubernetes/_k3s-config/configuration-provider.nix;
    slot = "configuration";
  };

  checkController = {
    result,
    controllerAlias,
    terminalAlias,
  }: let
    abilities = result.abilities;
    controller = abilities.implementations."k3s-combined:${controllerAlias}";
    terminal = abilities.implementations."k3s-combined:${terminalAlias}";
    desired = builtins.head (builtins.attrValues abilities.desiredResources);
    child = abilities.compositionRequests.${result.childRequestKey};
  in
    controller.providerModule
    != null
    && controller.handlerDescriptor == null
    && builtins.attrNames controller.requirements == ["effects"]
    && terminal.providerModule == null
    && terminal.handlerDescriptor != null
    && child.parameters == desired.value;

  transitionFor = {
    result,
    controllerAlias,
    terminalAlias,
    kind,
    duplicateTerminal ? false,
  }: let
    abilities = result.abilities;
    desired = builtins.head (builtins.attrValues abilities.desiredResources);
    controller = abilities.implementations."k3s-combined:${controllerAlias}";
    terminalDeclaration = abilities.interfaces."k3s-combined:${terminalAlias}";
    terminalInterface = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration terminalDeclaration
    );
    method =
      if kind == "remove"
      then "release"
      else if kind == "unchanged"
      then null
      else "apply";
    binding = {
      id = "terminal";
      request.consumer = desired.resource.provider;
      interface = terminalInterface;
      caller_grant = {
        methods = [
          "apply"
          "observe"
          "release"
        ];
        resources = lib.optional (method != null) {
          resource = desired.resource;
          access = "exclusive-write";
          operations = [method];
        };
      };
    };
    authorizedBinding = {
      authority =
        if kind == "remove"
        then {
          role = "teardown";
          source_request.consumer = desired.resource.provider;
        }
        else {role = "desired";};
      inherit binding;
    };
  in
    controller.transition {
      provider = desired.resource.provider;
      operation_scope = [controllerAlias];
      changes = [
        {
          inherit kind;
          resource = desired.resource;
          current = null;
          desired = null;
        }
      ];
      authorized_bindings =
        lib.optional (method != null) authorizedBinding
        ++ lib.optional duplicateTerminal authorizedBinding;
      controllers = lib.optional (method != null) {
        resource = desired.resource;
        controller = {
          provider = desired.resource.provider;
          group = controllerAlias;
        };
      };
    };
  transitionMethods = arguments:
    builtins.map (operation: operation.method) (transitionFor arguments).operations;
  duplicateRejected = arguments:
    !(builtins.tryEval (builtins.deepSeq (transitionFor (arguments // {duplicateTerminal = true;})) true)).success;
in
  assert checkController {
    result = object;
    controllerAlias = objectContract.controller.alias;
    terminalAlias = "kubernetes-object-effects";
  };
  assert checkController {
    result = configuration;
    controllerAlias = configurationContract.controller.alias;
    terminalAlias = "k3s-configuration-effects";
  };
  assert transitionMethods {
    result = object;
    controllerAlias = objectContract.controller.alias;
    terminalAlias = "kubernetes-object-effects";
    kind = "create";
  }
  == ["apply"];
  assert transitionMethods {
    result = object;
    controllerAlias = objectContract.controller.alias;
    terminalAlias = "kubernetes-object-effects";
    kind = "remove";
  }
  == ["release"];
  assert transitionMethods {
    result = configuration;
    controllerAlias = configurationContract.controller.alias;
    terminalAlias = "k3s-configuration-effects";
    kind = "reconcile-divergent";
  }
  == ["apply"];
  assert transitionMethods {
    result = configuration;
    controllerAlias = configurationContract.controller.alias;
    terminalAlias = "k3s-configuration-effects";
    kind = "unchanged";
  }
  == [];
  assert duplicateRejected {
    result = object;
    controllerAlias = objectContract.controller.alias;
    terminalAlias = "kubernetes-object-effects";
    kind = "create";
  };
  assert duplicateRejected {
    result = configuration;
    controllerAlias = configurationContract.controller.alias;
    terminalAlias = "k3s-configuration-effects";
    kind = "remove";
  }; true
