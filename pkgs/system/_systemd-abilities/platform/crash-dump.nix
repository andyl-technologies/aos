##! Selected systemd projection of the provider-neutral crash-dump policy.
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
    then {etc = {};}
    else
      import ./_crash-dump-configuration.nix {
        inherit policy;
        systemd = packageArtifactFor (lib.abilities.packageOutput {});
        coreutils = packageArtifactFor (lib.abilities.packageOutput {package = "coreutils";});
      };
in {
  config = lib.mkIf (selected != null) {environment.etc = rendered.etc;};
}
