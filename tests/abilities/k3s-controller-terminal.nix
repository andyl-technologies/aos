##! Verifies the K3s controllers delegate through one exact terminal binding.
{
  lib,
  pkgs,
}: let
  objectControllerAlias = "kubernetes-object-set";
  configurationControllerAlias = "k3s-configuration";
  controllerMethods = ["apply" "observe" "release"];

  evaluateController = {
    requestKey,
    requestInterfaceName,
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
            config.aos.abilities = {
              instances.workload = {};
              requirementTemplates.${requestKey} =
                lib.abilities.interfaceSelector {
                  name = requestInterfaceName;
                  abi = 1;
                }
                // {
                  description = "Selects the package-owned K3s controller under test.";
                  methods = requestMethods;
                  guarantees = [];
                  strength = "required";
                  fallback = null;
                };
              requests.${requestKey} = {
                requirement = requestKey;
                consumer = "workload";
                scope = [requestKey];
                inherit parameters;
              };
            };
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
    requestInterfaceName = "aos.kubernetes.object-set";
    requestMethods = controllerMethods;
    parameters = {
      cluster.prerequisites = [];
      contributions = {};
    };
    controllerAlias = objectControllerAlias;
    controllerInstance = "object-controller";
    terminalAlias = "kubernetes-object-effects";
    providerModule = ../../pkgs/kubernetes/_k3s-config/object-provider.nix;
    slot = "objects";
  };
  configuration = evaluateController {
    requestKey = "configuration";
    requestInterfaceName = "aos.k3s.configuration";
    requestMethods = controllerMethods;
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
    controllerAlias = configurationControllerAlias;
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
    controllerAlias = objectControllerAlias;
    terminalAlias = "kubernetes-object-effects";
  };
  assert checkController {
    result = configuration;
    controllerAlias = configurationControllerAlias;
    terminalAlias = "k3s-configuration-effects";
  };
  assert transitionMethods {
    result = object;
    controllerAlias = objectControllerAlias;
    terminalAlias = "kubernetes-object-effects";
    kind = "create";
  }
  == ["apply"];
  assert transitionMethods {
    result = object;
    controllerAlias = objectControllerAlias;
    terminalAlias = "kubernetes-object-effects";
    kind = "remove";
  }
  == ["release"];
  assert transitionMethods {
    result = configuration;
    controllerAlias = configurationControllerAlias;
    terminalAlias = "k3s-configuration-effects";
    kind = "reconcile-divergent";
  }
  == ["apply"];
  assert transitionMethods {
    result = configuration;
    controllerAlias = configurationControllerAlias;
    terminalAlias = "k3s-configuration-effects";
    kind = "unchanged";
  }
  == [];
  assert duplicateRejected {
    result = object;
    controllerAlias = objectControllerAlias;
    terminalAlias = "kubernetes-object-effects";
    kind = "create";
  };
  assert duplicateRejected {
    result = configuration;
    controllerAlias = configurationControllerAlias;
    terminalAlias = "k3s-configuration-effects";
    kind = "remove";
  }; true
