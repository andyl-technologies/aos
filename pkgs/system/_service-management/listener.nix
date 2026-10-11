##! Declares exclusive host listener ownership independently of daemon startup.
{lib, ...}: {
  aos.abilities.listener.operations.claim = {
    input.options = {
      transport = lib.mkOption {
        type = lib.types.enum ["tcp" "udp"];
        description = "Host transport reserved by the consumer.";
      };
      port = lib.mkOption {
        type = lib.types.ints.between 1 65535;
        description = "Host port reserved exclusively by the consumer.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Retained exclusive listener claim identity.";
    };
  };
}
