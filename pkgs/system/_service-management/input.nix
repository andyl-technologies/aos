##! Declares the complete manager-neutral input shared by services and effects.
{
  lib,
  name ? "service",
  ...
}: let
  schema = import ./types.nix {inherit lib;};
  fields = builtins.removeAttrs schema.serviceDeclarationFields ["service" "enabled" "activation_owner"];
in {
  _module.strict = true;

  options =
    builtins.mapAttrs schema.optionFor fields
    // {
      instance = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Domain instance key used for an unnamed manager resource.";
      };
      bootstrap = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Render this service into the image for startup before native activation; its normal handler retains lifecycle ownership.";
      };
      dependencyValues = lib.mkOption {
        type = lib.types.json;
        default = [];
        description = "Resolved prerequisite values included in service reconciliation identity.";
      };
      service = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "Stable service identity within this installation scope.";
      };
      enabled = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether the manager enables the service.";
      };
      auto_start = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether the manager starts the service during activation.";
      };
      activation_owner = lib.mkOption {
        type = lib.types.enum ["ability" "image" "manager"];
        default = "ability";
        description = "Lifecycle owner of the service.";
      };
      lifecycle = lib.mkOption {
        type = lib.types.nullOr schema.serviceDeclarationFields.lifecycle;
        default = null;
        description = "Commands and lifecycle behavior of the service.";
      };
      policy = lib.mkOption {
        type = import ./policy.nix {inherit lib;};
        default = {};
        description = "Manager-neutral process hardening and device policy.";
      };
    };
}
