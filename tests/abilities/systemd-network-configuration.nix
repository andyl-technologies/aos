##! Pure controller and terminal systemd network-configuration composition.
{
  lib,
  pkgs,
}: let
  artifactReference = {
    content = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-systemd";
    nar_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    closure = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  };
  systemdSelector = lib.abilities.packageOutput {};
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "network-configuration";
    dependencies.${builtins.toJSON {
      package = systemdSelector.package;
      output = systemdSelector.output;
    }} = artifactReference.store_path;
  };
  consumerFor = resolverEnabled: {lib, ...}: {
    config.aos.abilities = lib.mkMerge [
      {instances.application = {};}
      (lib.abilities.interfaces.serviceManagement.forProducer {
        consumerInstance = "application";
        key = "network";
        interface = lib.abilities.interfaces.networkConfiguration.interface;
        methods = ["apply" "observe" "remove"];
        parameters = {
          authority = "operator";
          links = [
            {
              kind = "ethernet";
              name = "host";
              selector = {
                kind = "mac";
                value = "02:00:00:00:00:01";
              };
              addressing = {
                dhcp = false;
                addresses = ["192.0.2.10/24"];
                gateway = "192.0.2.1";
                dns = ["192.0.2.53"];
              };
            }
          ];
          resolver = {
            enabled = resolverEnabled;
            nameservers = ["192.0.2.53"];
            search = ["example.test"];
            dnssec = "yes";
          };
          prerequisites = [];
        };
      })
    ];
  };
  consumer = consumerFor true;
  baseBindings."test:network" = {
    request = "consumer:network";
    implementation = "systemd:network-configuration";
    providerInstance = "systemd:manager";
    slot = "host";
  };
  evaluateFor = consumerModule: bindings:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        ./_systemd-platform-module.nix
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-network";
              stage = "host";
            };
            instances."systemd:manager" = {};
            inherit bindings;
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
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  evaluate = evaluateFor consumer;
  pending = evaluate baseBindings;
  pendingChildren = builtins.attrValues pending.config.aos.abilities.compositionPendingRequests;
  childrenFor = requirement:
    builtins.filter (child: child.requirement == requirement) pendingChildren;
  networkEffectsChild = builtins.head (childrenFor "network-configuration-effects");
  networkServiceChildren = childrenFor "network-service-unit";
  disabledResolverPending = evaluateFor (consumerFor false) baseBindings;
  disabledResolverServiceChildren = builtins.filter
    (child: child.requirement == "network-service-unit")
    (builtins.attrValues disabledResolverPending.config.aos.abilities.compositionPendingRequests);
  abilities = pending.config.aos.abilities;
  networkInterface = lib.abilities.interfaces.networkConfiguration.interface;
  effectsInterface = networkInterface.effects;
  emptyInput = lib.abilities.types.record {fields = {};};
  resource = {
    resource = {
      provider = "systemd:manager";
      key = "host";
    };
    kind = networkInterface.identity.name;
    lifetime = "persistent";
  };
  transition = abilities.implementations."systemd:network-configuration".transition;
  transitionOperation = kind: let
    method =
      if kind == "remove"
      then "remove"
      else "apply";
    fragment = transition {
      provider = resource.resource.provider;
      operation_scope = ["network-configuration"];
      before.resources = [resource];
      after.resources = [resource];
      changes = [
        {
          inherit kind;
          inherit (resource) resource;
          current = null;
          desired = null;
        }
      ];
      authorized_bindings = [
        {
          authority.role =
            if kind == "remove"
            then "teardown"
            else "desired";
          binding = {
            id = "network-configuration-effects";
            interface = effectsInterface.identity;
            caller_grant = {
              methods = effectsInterface.methods;
              resources = [
                {
                  inherit (resource) resource;
                  access = "exclusive-write";
                  operations = [method];
                }
              ];
            };
          };
        }
      ];
      controllers = [
        {
          inherit (resource) resource;
          controller = {
            provider = resource.resource.provider;
            group = "network-configuration";
          };
        }
      ];
    };
  in
    builtins.head fragment.operations;
  applyOperation = transitionOperation "create";
  removeOperation = transitionOperation "remove";
  networkdChild = builtins.head (builtins.filter (child: child.slot == "systemd-networkd") networkServiceChildren);
  resolvedChild = builtins.head (builtins.filter (child: child.slot == "systemd-resolved") networkServiceChildren);
in
  assert networkEffectsChild.requirement == "network-configuration-effects";
  assert networkEffectsChild.declaration.parameters == {};
  assert builtins.length networkServiceChildren == 2;
  assert builtins.length disabledResolverServiceChildren == 1;
  assert (builtins.head disabledResolverServiceChildren).slot == "systemd-networkd";
  assert networkdChild.declaration.parameters.source
  == {
    artifact = lib.abilities.packageOutput {};
    unit_file = "lib/systemd/system/systemd-networkd.service";
    unit_name = "systemd-networkd.service";
  };
  assert resolvedChild.declaration.parameters.source
  == {
    artifact = lib.abilities.packageOutput {};
    unit_file = "lib/systemd/system/systemd-resolved.service";
    unit_name = "systemd-resolved.service";
  };
  assert builtins.all (child: child.declaration.parameters.activation == "enabled") networkServiceChildren;
  assert effectsInterface.identity.name == "aos.network.configuration-effects";
  assert builtins.length pendingChildren == 3;
  assert builtins.isFunction abilities.implementations."systemd:network-configuration".transition;
  assert abilities.implementations."systemd:network-configuration".handlerDescriptor == null;
  assert abilities.implementations."systemd:network-configuration-effects".providerModule == null;
  assert abilities.implementations."systemd:network-configuration-effects".interface == effectsInterface.alias;
  assert !(abilities.interfaces ? "systemd:systemd-network-configuration-effects");
  assert lib.abilities.types.schemaOf "network apply method" networkInterface.declaration.methods.apply.parameters
  == lib.abilities.types.schemaOf "network apply input" networkInterface.types.applyInput;
  assert (lib.abilities.types.schemaOf "network apply input" networkInterface.types.applyInput).fields.bootstrap.value
  == lib.abilities.types.schemaOf "network bootstrap" networkInterface.types.bootstrap;
  assert builtins.attrNames (lib.abilities.types.schemaOf "network bootstrap" networkInterface.types.bootstrap).fields.selector.variants
  == ["mac" "name"];
  assert lib.abilities.types.schemaOf "network observe parameters" networkInterface.declaration.methods.observe.parameters
  == lib.abilities.types.schemaOf "network empty input" emptyInput;
  assert lib.abilities.types.schemaOf "network remove parameters" networkInterface.declaration.methods.remove.parameters
  == lib.abilities.types.schemaOf "network empty input" emptyInput;
  assert lib.abilities.types.schemaOf "network effects observe parameters" effectsInterface.declaration.methods.observe.parameters
  == lib.abilities.types.schemaOf "network empty input" emptyInput;
  assert lib.abilities.types.schemaOf "network effects remove parameters" effectsInterface.declaration.methods.remove.parameters
  == lib.abilities.types.schemaOf "network empty input" emptyInput;
  assert applyOperation.interface == effectsInterface.identity;
  assert applyOperation.method == "apply";
  assert applyOperation.target.interface == networkInterface.identity;
  assert applyOperation.inputs.value == {bootstrap = null;};
  assert removeOperation.method == "remove";
  assert pending.config.systemd.providerNetworkConfigurationPlans == []; true
