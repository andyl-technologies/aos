##! Defines network prerequisites without coupling consumers to a manager.
{lib, ...}: {
  imports = [./network-configuration.nix];
  aos.abilities.network.operations.ready = {
    input.options = {
      required = lib.mkOption {
        type = lib.types.deferred lib.types.bool;
        default = true;
        description = "Wait for readiness when this prerequisite is required.";
      };
      families = lib.mkOption {
        type = lib.types.listOf (lib.types.enum ["ipv4" "ipv6"]);
        default = ["ipv4" "ipv6"];
        description = "Address families required by the consumer.";
      };
      scope = lib.mkOption {
        type = lib.types.enum ["stack-prepared" "address-configured"];
        default = "stack-prepared";
        description = "Required network readiness level.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Established network readiness resource identity.";
    };
  };
}
