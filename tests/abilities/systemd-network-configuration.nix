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
    artifactLocators.${builtins.toJSON {
      package = systemdSelector.package;
      output = systemdSelector.output;
    }} = {
      path = artifactReference.store_path;
      inherit artifactReference;
    };
  };
  consumer = {lib, ...}: {
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
            enabled = true;
            nameservers = ["192.0.2.53"];
            search = ["example.test"];
            dnssec = "yes";
          };
          prerequisites = [];
        };
      })
    ];
  };
  baseBindings."test:network" = {
    request = "consumer:network";
    implementation = "systemd:network-configuration";
    providerInstance = "systemd:manager";
    slot = "host";
  };
  evaluate = bindings:
    lib.evalModules {
      inherit lib;
      modules =
        [
          lib.abilities.module
          ../../modules/systemd/system.nix
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
        ]
        ++ builtins.map lib.authenticatedModule [
          {
            name = "systemd";
            inherit (pkgs.systemd) version;
            module = pkgs.systemd.module + "/module.nix";
          }
          {
            name = "consumer";
            module = consumer;
          }
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
  pending = evaluate baseBindings;
  child = builtins.head (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests);
  resolved = evaluate (baseBindings
    // {
      "test:network-effects" = {
        request = child.request;
        implementation = "systemd:network-configuration-effects";
        providerInstance = "systemd:manager";
        slot = child.slot;
      };
    });
  abilities = resolved.config.aos.abilities;
  resource = builtins.head (builtins.attrValues abilities.desiredResources);
  networkInterface = lib.abilities.interfaces.networkConfiguration.interface;
  effectsInterface = networkInterface.effects;
  emptyInput = lib.abilities.types.record {fields = {};};
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
in
  assert child.requirement == "network-configuration-effects";
  assert child.declaration.parameters == {};
  assert effectsInterface.identity.name == "aos.network.configuration-effects";
  assert abilities.compositionPendingRequests == {};
  assert resource.kind == "aos.network.configuration";
  assert !(resource.value ? bootstrap);
  assert resource.lifetime == "persistent";
  assert resource.realization.systemd.store_path == artifactReference.store_path;
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
  assert builtins.length resolved.config.systemd.providerNetworkConfigurationArtifacts == 1; true
