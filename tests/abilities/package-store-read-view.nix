##! Selected systemd implementation of the provider-neutral package-store view.
{
  lib,
  pkgs,
}: let
  readView = lib.abilities.interfaces.packageStoreReadView.interfaces.readView;
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "package-store-read-view";
  };
  staticContract = pkgs.writeTextFile {
    name = "package-store-read-view-test-contract";
    destination = "/contract.json";
    text = ''{"schema":"aos.static-ability-contract/v1"}'';
  };
  consumerModule = {
    config.aos.abilities = {
      instances.image = {};
      requirementTemplates.package-store-read-view = {
        interface = readView.identity.name;
        inherit (readView.identity) abi descriptor;
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      requests.package-store-read-view = {
        requirement = "package-store-read-view";
        consumer = "image";
        scope = ["boot-image"];
        parameters.scope = "boot-image";
      };
    };
  };
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      ../../modules/base/_kernel-parameter-contributions.nix
      {
        options.system.build.staticAbilityContract = lib.mkOption {
          type = lib.types.package;
          readOnly = true;
        };
        config = {
          system.build.staticAbilityContract = staticContract;
          aos.abilities = {
            environment = {
              authority = "test";
              key = "package-store-read-view";
              stage = "host";
            };
            bindings.selected = {
              request = "consumer:package-store-read-view";
              implementation = "systemd:package-store-read-view";
              providerInstance = "systemd:package-store-read-view";
              slot = "boot-image";
            };
          };
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
    selectedProviderModules = [selectedProvider];
    specialArgs = {
      inherit pkgs;
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  abilities = evaluated.config.aos.abilities;
  provided = abilities.implementations."systemd:package-store-read-view".provide {
    instance.id = abilities.instanceIdentities."systemd:package-store-read-view";
    requests."consumer:package-store-read-view" = abilities.requests."consumer:package-store-read-view";
    bindings.selected = abilities.bindings.selected;
    children = {};
  };
  outputs = abilities.compositionOutputs."consumer:package-store-read-view";
  locator = {
    schema = "aos.package-store.read-view-locator/v1";
    identity_root = "/nix/store";
    read_root = "/nix.lower/store";
    static_contract = "${staticContract}/contract.json";
  };
  expectedResource = {
    interface = readView.identity;
    resource = {
      provider = abilities.instanceIdentities."systemd:package-store-read-view";
      key = "boot-image";
    };
    operations = ["observe"];
    lifetime = "persistent";
  };
in
  assert provided.outputs."consumer:package-store-read-view" == {
    inherit locator;
    read-view-resource = expectedResource;
  };
  assert outputs.locator.value == locator;
  assert outputs.read-view-resource.value == expectedResource;
  assert !(outputs ? identity-root);
  assert !(outputs ? read-root);
  assert !(outputs ? static-contract); true
