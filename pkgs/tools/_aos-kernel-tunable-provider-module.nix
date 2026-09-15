##! Procfs implementation of the canonical kernel-tunable interface.
{lib, ...}: let
  interface = lib.abilities.interfaces.kernelTunables.interface;
  artifact = lib.abilities.packageOutput {};
in {
  config.aos.abilities.implementations.kernel-tunables = {
    description = "Converges Linux kernel tunables through the checked procfs ABI.";
    interface = interface.identity;
    inherit artifact;
    inherit (interface) methods;
    guarantees = [];
    providerModule = {
      inherit artifact;
      path = "share/aos/providers/kernel-tunables.nix";
    };
    handlerDescriptor = {
      inherit artifact;
      entryPoint = "bin/aos-kernel-tunable-provider";
      arguments = interface.requestType;
      result = interface.observationType;
    };
    desiredType = interface.realizationType;
    requiredFeatures = [];
  };
}
