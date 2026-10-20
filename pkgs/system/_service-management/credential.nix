##! Defines opaque credential delivery without carrying secret bytes in modules.
{lib, ...}: {
  aos.abilities.credential.operations.deliver = {
    input.options = {
      name = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Provider-neutral credential name; supply exactly one name or resource.";
      };
      resource = lib.mkOption {
        type = lib.types.nullOr (lib.types.deferred lib.types.str);
        default = null;
        description = "Checked credential source path from another operation.";
      };
      scope = lib.mkOption {
        type = lib.types.enum ["system" "user"];
        default = "system";
        description = "Credential source namespace.";
      };
      encrypted = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Require an encrypted credential source and delivery channel.";
      };
    };
    result.options = {
      path = lib.mkOption {
        type = lib.types.str;
        description = "Private credential view owned by this effect.";
      };
      resource = lib.mkOption {
        type = lib.types.str;
        description = "Delivered credential resource identity.";
      };
    };
  };
}
