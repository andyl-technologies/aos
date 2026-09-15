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
          bootstrap = {
            selector = {
              kind = "mac";
              value = "02:00:00:00:00:01";
            };
            addresses = ["198.51.100.10/24"];
            gateway = "198.51.100.1";
            dns = ["198.51.100.53"];
          };
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
      modules = [
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
      ];
      packageModules = [
        {
          name = "systemd";
          inherit (pkgs.systemd) version;
          module = pkgs.systemd.module + "/module.nix";
        }
        {
          name = "consumer";
          module = consumer;
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
  pending = evaluate baseBindings;
  child = builtins.head (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests);
  resolved = evaluate (baseBindings
    // {
      "test:network-effects" = {
        request = child.request;
        implementation = "systemd:systemd-network-configuration-effects";
        providerInstance = "systemd:manager";
        slot = child.slot;
      };
    });
  abilities = resolved.config.aos.abilities;
  resource = builtins.head (builtins.attrValues abilities.desiredResources);
in
  assert child.requirement == "network-configuration-effects";
  assert abilities.compositionPendingRequests == {};
  assert resource.kind == "aos.network.configuration";
  assert resource.lifetime == "persistent";
  assert resource.realization.systemd.store_path == artifactReference.store_path;
  assert builtins.isFunction abilities.implementations."systemd:network-configuration".transition;
  assert abilities.implementations."systemd:network-configuration".handlerDescriptor == null;
  assert abilities.implementations."systemd:systemd-network-configuration-effects".providerModule == null;
  assert builtins.length resolved.config.systemd.providerNetworkConfigurationArtifacts == 1; true
