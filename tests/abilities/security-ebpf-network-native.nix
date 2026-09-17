##! Checks the package-owned BPF network resource through the complete fixed point.
{
  lib,
  pkgs,
}: let
  packageName = "aos-ebpf-net-policy";
  controllerAlias = "ebpf-cgroup-network-policy";
  terminalAlias = "ebpf-cgroup-network-policy-effects";
  instance = "${packageName}:ebpf-cgroup-network-policy";
  requestKey = "${packageName}:cgroup-policy-set";
  childRequestKey = lib.abilities.compositionRequestKey {
    implementation = "${packageName}:${controllerAlias}";
    providerInstance = instance;
    key = "cgroup-policy-set";
  };
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-ebpf-net-policy;
    implementation = controllerAlias;
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.security.ebpfNetworkPolicy.enable = true;
        aos.security.ebpfNetworkPolicy.policies = [
          {
            name = "sample";
            cgroup = "/sys/fs/cgroup/aos/sample.service";
            policy = {
              artifact = lib.abilities.packageOutput {package = packageName;};
              path = "share/aos/ebpf-net/sample-policy.json";
            };
            object = {
              artifact = lib.abilities.packageOutput {package = packageName;};
              path = "lib/bpf/aos-ebpf-net-policy.bpf.o";
            };
          }
        ];
        aos.abilities = {
          environment = {
            authority = "test";
            key = "ebpf-network";
            stage = "host";
          };
          bindings."test:controller" = {
            request = requestKey;
            implementation = "${packageName}:${controllerAlias}";
            providerInstance = instance;
            slot = "cgroup-policy-set";
          };
          bindings."test:terminal" = {
            request = childRequestKey;
            implementation = "${packageName}:${terminalAlias}";
            providerInstance = instance;
            slot = "cgroup-policy-set";
          };
        };
      }
    ];
    packageModules = [
      {
        name = packageName;
        inherit (pkgs.aos-ebpf-net-policy) version;
        module = pkgs.aos-ebpf-net-policy.module + "/module.nix";
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
  assert policy.name == "sample";
  assert policy.cgroup == "/sys/fs/cgroup/aos/sample.service";
  assert policy.policy.path == "share/aos/ebpf-net/sample-policy.json";
  assert policy.object.path == "lib/bpf/aos-ebpf-net-policy.bpf.o";
  assert desired.kind == "aos.network.ebpf-cgroup-policy";
  assert desired.lifetime == "instance";
  assert desired.realization.schema == "aos.linux.ebpf-net-policy-realization/v1";
  assert desired.realization.loader.entry_point == "libexec/aos-ebpf-net-policy-loader";
  assert desired.realization.pin_directory == "/sys/fs/bpf/aos/network";
  assert output.value.resource == desired.resource;
  assert output.value.operations == ["observe"];
  assert controller.handlerDescriptor == null;
  assert controller.providerModule.path == "provider.nix";
  assert terminal.providerModule == null;
  assert terminal.handlerDescriptor.entryPoint == "bin/aos-ebpf-net-policy-provider";
  assert transitionMethods "create" == ["apply"];
  assert transitionMethods "update" == ["apply"];
  assert transitionMethods "reconcile-stopped" == ["apply"];
  assert transitionMethods "reconcile-divergent" == ["apply"];
  assert transitionMethods "unchanged" == [];
  assert transitionMethods "remove" == ["remove"]; true
