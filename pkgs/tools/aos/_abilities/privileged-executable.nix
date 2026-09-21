##! AOS runtime-layout implementation of privileged executable materialization.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  executable = serviceManagement.interfaces.privilegedExecutable;
  filesystemEntry = serviceManagement.interfaces.filesystemEntry;
in {
  config.aos.abilities.implementations.privileged-executable = {
    description = "Materializes privileged package executables in the AOS runtime wrapper layout.";
    interface = executable.identity;
    artifact = lib.abilities.packageOutput {};
    inherit (executable) methods;
    guarantees = [];
    requirements.filesystem-entry = {
      alias = "filesystem-entry";
      description = "Materializes the selected runtime directories and package executable.";
      accepted_interfaces = [filesystemEntry.identity];
      inherit (filesystemEntry) methods;
      guarantees = [];
      strength = "required";
      fallback = null;
    };
    providerModule = {
      artifact = lib.abilities.packageOutput {output = "module";};
      path = "privileged-executable-provider.nix";
    };
    desiredType = null;
    requiredFeatures = [];
  };
}
