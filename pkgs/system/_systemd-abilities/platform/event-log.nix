##! Selected systemd projection of the provider-neutral event-log policy.
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
  config = lib.mkIf (selected != null) {environment.etc = configuration;};
}
