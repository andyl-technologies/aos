##! Renders provider-neutral runtime entries through the selected systemd manager.
{
  abilitySelection ? null,
  lib,
  ...
}: let
  selectedBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "runtime-entry-population";
  entries = builtins.concatMap (selected: selected.request.value.parameters.entries) selectedBindings;
  entriesByPath = builtins.foldl' (result: entry:
    result
    // {
      ${entry.path} = (result.${entry.path} or []) ++ [entry];
    }) {}
  entries;
  conflictingPaths = builtins.filter (path: let
    definitions = entriesByPath.${path};
  in
    builtins.any (entry: entry != builtins.head definitions) definitions)
  (builtins.attrNames entriesByPath);
  uniqueEntries =
    builtins.map
    (path: builtins.head entriesByPath.${path})
    (builtins.attrNames entriesByPath);
  directiveFor = entry: "${
    if entry.kind == "directory"
    then "d"
    else "f"
  } ${entry.path} ${entry.mode} ${entry.owner} ${entry.group} -";
in {
  config =
    lib.mkIf (
      selectedBindings != []
    ) {
      assertions = [
        {
          assertion = conflictingPaths == [];
          message = "runtime filesystem entries disagree for: ${lib.concatStringsSep ", " conflictingPaths}";
        }
      ];

      environment.etc."tmpfiles.d/aos-runtime-entries.conf".text = ''
        # Generated from bound runtime-entry-population ability requests.
        ${lib.concatMapStringsSep "\n" directiveFor uniqueEntries}
      '';
    };
}
