##! Systemd implementation of the provider-neutral event-log policy.
{
  abilitySelection ? null,
  lib,
  ...
}: let
  interface = lib.abilities.interfaces.eventLogPolicy.interface;
  selectedBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation interface.alias;
  selected =
    if selectedBindings == []
    then null
    else if builtins.length selectedBindings == 1
    then builtins.head selectedBindings
    else throw "the systemd event-log implementation requires exactly one selected policy";
  policy =
    if selected == null
    then null
    else selected.request.value.parameters;
  configuration =
    if policy == null
    then {}
    else import ./_event-log-configuration.nix {inherit policy;};
in {
  config = lib.mkMerge [
    {
      aos.abilities.implementations.${interface.alias} = {
        description = "Realizes provider-neutral event-log policy through systemd-journald.";
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
    (lib.mkIf (selected != null) {environment.etc = configuration;})
  ];
}
