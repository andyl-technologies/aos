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
    slot,
  }: let
    selectedProvider = import ./_selected-package-provider.nix {
      inherit lib;
      package = pkgs.k3s-combined;
      implementation = controllerAlias;
    };
    systemdModule = lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd;
    packageModules = [
      (systemdModule
        // {module = "${systemdModule.configRoot}/linux-service-features.nix";})
      {
        name = "k3s-combined";
        version = pkgs.k3s-combined.version;
        module = pkgs.k3s-combined.module + "/module.nix";
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
    evaluate = selection:
      lib.evalModules {
        inherit lib packageModules;
        modules = [
          lib.abilities.module
          {
            aos.abilities = {
              environment = {
                authority = "test";
                key = "k3s-controller-terminal";
                stage = "host";
              };
              instances =
                {"k3s-combined:${controllerInstance}" = {};}
                // selection.instances;
              bindings =
                {
                  "test:controller" = {
                    request = "consumer:${requestKey}";
                    implementation = "k3s-combined:${controllerAlias}";
                    providerInstance = "k3s-combined:${controllerInstance}";
                    inherit slot;
                  };
                }
                // selection.bindings;
            };
          }
        ];
        selectedProviderModules = [selectedProvider];
        specialArgs.abilityResolution = {
          inherit (selection) requests requirements;
        };
      };
    initial = evaluate {
      instances = {};
      bindings = {};
      requests = {};
      requirements = {};
    };
    selected = import ../../lib/build/select-ability-bindings.nix {
      inherit lib;
      abilities = initial.config.aos.abilities;
    };
    evaluated = evaluate selected;
    childRequestKeys = builtins.attrNames selected.requests;
    childRequestKey =
      if builtins.length childRequestKeys == 1
      then builtins.head childRequestKeys
      else throw "K3s controller selection must resolve one terminal request";
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
    && terminal.handlerDescriptor.entryPoint == "libexec/aos-kubernetes-provider"
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
