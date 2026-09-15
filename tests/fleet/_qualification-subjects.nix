##! Selects qualification cells from the authenticated package-derived matrix.
{
  lib,
  matrix,
}: let
  adaptersByName = builtins.listToAttrs (map (adapter: {
      name = adapter.adapter;
      value = adapter;
    })
    matrix.spec.surface.adapters);
  scenarioFor = cell: let
    matches = builtins.filter (
      scenario: lib.hasSuffix "/${scenario.id}" cell.id
    ) matrix.spec.surface.scenarios;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "qualification cell '${cell.id}' does not select exactly one package-derived scenario";
  subjectFor = cell: {
    inherit cell;
    adapter = adaptersByName.${cell.adapter}
      or (throw "qualification cell '${cell.id}' names an absent package-derived adapter");
    scenario = scenarioFor cell;
  };
  applicableSubjects = map subjectFor matrix.applicable_cells;
in {
  select = {
    scopes,
    accepts,
  }: let
    selected = builtins.filter (
      subject:
        builtins.elem subject.adapter.scope scopes
        && accepts subject
    ) applicableSubjects;
    cellIds = map (subject: subject.cell.id) selected;
  in
    assert scopes != [];
    assert builtins.length cellIds == builtins.length (lib.unique cellIds); cellIds;
}
