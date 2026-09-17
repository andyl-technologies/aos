##! Checks the package-owned BPF-LSM resource through the complete fixed point.
{
  lib,
  pkgs,
}: let
  packageName = "aos-ebpf-lsm-policy";
  controllerAlias = "ebpf-lsm-policy-set";
  terminalAlias = "ebpf-lsm-policy-effects";
  instance = "${packageName}:ebpf-lsm-policy";
  requestKey = "${packageName}:policy-set";
  childRequestKey = lib.abilities.compositionRequestKey {
    implementation = "${packageName}:${controllerAlias}";
    providerInstance = instance;
    key = "policy-set";
  };
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-ebpf-lsm-policy;
    implementation = controllerAlias;
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.security.ebpfLsm.enable = true;
        aos.abilities = {
          environment = {
            authority = "test";
            key = "ebpf-lsm";
            stage = "host";
          };
          bindings."test:controller" = {
            request = requestKey;
            implementation = "${packageName}:${controllerAlias}";
            providerInstance = instance;
            slot = "policy-set";
          };
          bindings."test:terminal" = {
            request = childRequestKey;
            implementation = "${packageName}:${terminalAlias}";
            providerInstance = instance;
            slot = "policy-set";
          };
        };
      }
    ];
    packageModules = [
      {
        name = packageName;
        inherit (pkgs.aos-ebpf-lsm-policy) version;
        module = pkgs.aos-ebpf-lsm-policy.module + "/module.nix";
      }
    ];
    selectedProviderModules = [selectedProvider];
  };
  abilities = evaluated.config.aos.abilities;
  request = abilities.requests.${requestKey};
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  controller = abilities.implementations."${packageName}:${controllerAlias}";
  terminal = abilities.implementations."${packageName}:${terminalAlias}";
  output = abilities.compositionOutputs.${requestKey}.readiness-resource;
  effectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration abilities.interfaces."${packageName}:${terminalAlias}"
  );
  transitionMethods = kind: let
    method =
      if kind == "remove"
      then "remove"
      else if kind == "unchanged"
      then null
      else "apply";
    binding = {
      id = "terminal";
      request.consumer = desired.resource.provider;
      interface = effectsIdentity;
      caller_grant = {
        methods = ["apply" "observe" "remove"];
        resources = lib.optional (method != null) {
          resource = desired.resource;
          access = "exclusive-write";
          operations = [method];
        };
      };
    };
    fragment = controller.transition {
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
      authorized_bindings = lib.optional (method != null) {
        authority =
          if kind == "remove"
          then {
            role = "teardown";
            source_request.consumer = desired.resource.provider;
          }
          else {role = "desired";};
        inherit binding;
      };
      controllers = lib.optional (method != null) {
        resource = desired.resource;
        controller = {
          provider = desired.resource.provider;
          group = controllerAlias;
        };
      };
    };
  in
    builtins.map (operation: operation.method) fragment.operations;
  policy = builtins.head request.parameters.policies;
in
  assert abilities.compositionPendingRequests == {};
  assert abilities.compositionRequests.${childRequestKey}.parameters == desired.value;
  assert policy.name == "aos-lsm-task-audit";
  assert policy.policy.path == "share/aos/ebpf-lsm/aos-task-audit.json";
  assert policy.object.path == "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o";
  assert policy.programs == ["aos_lsm_file_mprotect"];
  assert desired.kind == "aos.security.ebpf-lsm-policy-set";
  assert desired.lifetime == "instance";
  assert desired.realization.schema == "aos.linux.ebpf-lsm-policy-realization/v1";
  assert desired.realization.loader.entry_point == "libexec/aos-ebpf-lsm-loader";
  assert desired.realization.pin_directory == "/sys/fs/bpf/aos/lsm";
  assert output.value.resource == desired.resource;
  assert output.value.operations == ["observe"];
  assert controller.handlerDescriptor == null;
  assert controller.providerModule.path == "provider.nix";
  assert terminal.providerModule == null;
  assert terminal.handlerDescriptor.entryPoint == "bin/aos-ebpf-lsm-provider";
  assert transitionMethods "create" == ["apply"];
  assert transitionMethods "update" == ["apply"];
  assert transitionMethods "reconcile-stopped" == ["apply"];
  assert transitionMethods "reconcile-divergent" == ["apply"];
  assert transitionMethods "unchanged" == [];
  assert transitionMethods "remove" == ["remove"]; true
