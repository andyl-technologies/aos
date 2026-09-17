##! Systemd implementation of the provider-neutral crash-dump policy.
{
  abilitySelection ? null,
  lib,
  packageArtifactFor,
  ...
}: let
  interface = lib.abilities.interfaces.crashDumpPolicy.interface;
  selectedBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation interface.alias;
  selected =
    if selectedBindings == []
    then null
    else if builtins.length selectedBindings == 1
    then builtins.head selectedBindings
    else throw "the systemd crash-dump implementation requires exactly one selected policy";
  policy =
    if selected == null
    then null
    else selected.request.value.parameters;
  rendered =
    if policy == null
    then null
    else
      import ./_crash-dump-configuration.nix {
        inherit policy;
        systemd = packageArtifactFor (lib.abilities.packageOutput {});
        coreutils = packageArtifactFor (lib.abilities.packageOutput {package = "coreutils";});
      };
  kernelTunables =
    if rendered == null
    then null
    else
      lib.abilities.interfaces.serviceManagement.forProducer {
        consumerInstance = "systemd:crash-dump-policy";
        key = "crash-dump-kernel-tunable";
        interface = lib.abilities.interfaces.kernelTunables.interface;
        methods = lib.abilities.interfaces.kernelTunables.interface.methods;
        parameters = {
          values."kernel.core_pattern" = rendered.corePattern;
          dependencies = [];
        };
      };
in {
  config = lib.mkMerge [
    {
      aos.abilities.implementations.${interface.alias} = {
        description = "Realizes provider-neutral crash-dump policy through systemd-coredump.";
        interface = interface.identity;
        artifact = lib.abilities.packageOutput {};
        methods = [];
        guarantees = [];
        providerModule = {
          artifact = lib.abilities.packageOutput {output = "module";};
          path = "provider/systemd.nix";
        };
        requiredFeatures = [];
      };
    }
    (lib.mkIf (selected != null) {
      environment.etc = rendered.etc;
      aos.abilities = lib.mkMerge [
        {instances."systemd:crash-dump-policy" = {};}
        kernelTunables
      ];
    })
  ];
}
