##! Owns the native service contract and derives effects from merged services.
{
  config,
  lib,
  ...
}: let
  operation = config.aos.abilities.serviceManagement.operations.realize;
  inputOptions = lib.submoduleOptions (lib.types.submodule operation.input) [];
  fields = builtins.attrNames (builtins.removeAttrs inputOptions ["_module"]);

  enabledServices = lib.filterAttrs (_: service: service.enable) config.aos.services;
  managerNames = builtins.concatMap (name: let
    service = enabledServices.${name};
    identity = service.manager_identity;
  in
    if service.instantiation != null && service.instantiation.kind != "singleton"
    then []
    else
      [
        (
          if identity == null
          then
            (
              if service.service == ""
              then name
              else service.service
            )
          else identity.name
        )
      ]
      ++ (
        if identity == null
        then []
        else identity.aliases
      )) (builtins.attrNames enabledServices);
  uniqueManagerNames = builtins.length managerNames == builtins.length (lib.unique managerNames);

  effectFor = name: service:
    if service.lifecycle == null
    then throw "Enabled service ${name} has no lifecycle configuration."
    else {
      after = service.activationAfter ++ service.bootstrapPrincipals;
      input =
        builtins.listToAttrs (builtins.map (field: {
            name = field;
            value = service.${field};
          })
          fields)
        // {
          instance = name;
          dependencyValues = service.activationInputs;
          enabled = service.enable;
          auto_start = service.autoStart;
          activation_owner = service.activationOwner;
        };
    };
in {
  imports = [
    ./execution.nix
    ./identity.nix
    ./network.nix
    ./device.nix
    ./configuration.nix
    ./credential.nix
    ./mount.nix
    ./watchdog.nix
    ./listener.nix
  ];

  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule [
      operation.input
      ({name, ...}: {config.service = lib.mkDefault name;})
      {
        options = {
          activationInputs = lib.mkOption {
            type = lib.types.listOf lib.types.effectOutput;
            default = [];
            description = "Consumed prerequisite values whose changes reconcile this service.";
          };
          activationAfter = lib.mkOption {
            type = lib.types.listOf lib.types.effectOutput;
            default = [];
            description = "Typed outputs that must be established before activating this service.";
          };
          enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Enable this service instance.";
          };
          autoStart = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Start this service during activation.";
          };
          bootstrapPrincipals = lib.mkOption {
            type = lib.types.listOf lib.types.effectOutput;
            default = [];
            description = "Native principal outputs required by early startup, seeded from their exact declared identities and consumed during activation.";
          };
          activationOwner = lib.mkOption {
            type = lib.types.enum ["ability" "image" "manager"];
            default = "ability";
            description = "Select the owner of service lifecycle changes.";
          };
        };
      }
    ]);
    default = {};
    extensible = true;
    description = "Service configurations checked by the selected operation input schema.";
  };

  config.aos.abilities.serviceManagement.operations.realize = {
    input = ./input.nix;
    result.options = {
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Service manager resource identity.";
      };
      path = lib.mkOption {
        type = lib.types.str;
        description = "Installed service definition path.";
      };
    };
    effects =
      if uniqueManagerNames
      then builtins.mapAttrs effectFor enabledServices
      else throw "Enabled services declare conflicting manager names or aliases.";
  };
}
