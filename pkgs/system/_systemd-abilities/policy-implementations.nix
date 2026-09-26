##! Package-owned systemd implementations of provider-neutral host policies.
{lib, ...}: let
  artifact = lib.abilities.packageOutput {};
  providerModule = {
    artifact = lib.abilities.packageOutput {output = "module";};
    path = "provider/systemd.nix";
  };
  implementation = interface: description: {
    inherit description artifact providerModule;
    interface = interface.identity;
    methods = [];
    guarantees = [];
    requiredFeatures = [];
  };
  eventLogPolicy = lib.abilities.interfaces.eventLogPolicy.interface;
  crashDumpPolicy = lib.abilities.interfaces.crashDumpPolicy.interface;
  loginSessionTracking = lib.abilities.interfaces.loginSessionTracking.interface;
  kernelTunables = lib.abilities.interfaces.kernelTunables.interface;
in {
  config.aos.abilities.implementations = {
    ${eventLogPolicy.alias} =
      implementation eventLogPolicy
      "Realizes provider-neutral event-log policy through systemd-journald.";

    ${crashDumpPolicy.alias} =
      (implementation crashDumpPolicy
        "Realizes provider-neutral crash-dump policy through systemd-coredump.")
      // {
        requirements.kernel-tunables = {
          alias = "kernel-tunables";
          description = "Converges the kernel core-pattern selected by the crash-dump policy.";
          accepted_interfaces = [kernelTunables.identity];
          methods = kernelTunables.methods;
          guarantees = [];
          strength = "required";
          fallback = null;
        };
      };

    ${loginSessionTracking.alias} =
      implementation loginSessionTracking
      "Registers authenticated login sessions through pam_systemd.";
  };
}
