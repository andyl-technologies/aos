##! Package-owned privileged helper request for terminal accounting.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.utempter;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  wrapper = serviceManagement.forProducer {
    consumerInstance = "runtime";
    key = "wrapper-utempter";
    interface = serviceManagement.interfaces.privilegedExecutable;
    methods = ["observe"];
    parameters = {
      name = "utempter";
      source = {
        artifact = lib.abilities.packageOutput {};
        path = "lib/utempter/utempter";
      };
      owner = "root";
      group = "utmp";
      mode = "2711";
      maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
    };
  };
  contribution = serviceManagement.splitContribution wrapper;
in {
  options.aos.security.utempter.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    description = "Allow terminal programs to update utmp through libutempter.";
  };

  config = lib.mkMerge [
    {aos.abilities = contribution.declarations;}
    (lib.mkIf (cfg.enable && config.aos.abilities.environment != null) {
      aos.abilities = lib.mkMerge [
        {instances.runtime = {};}
        contribution.configured
      ];
    })
  ];
}
