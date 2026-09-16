##! Resolves execution-stage policy against selected package declarations.
{
  lib,
  nativeAdapterMatrix,
  stagePolicy,
}: let
  declarations = nativeAdapterMatrix.container_execution_declarations;
  selectDeclaration = stage: policy: let
    matches = builtins.filter (declaration: declaration.scope == policy.scope) declarations;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "Container execution stage '${stage}' must resolve exactly one selected package declaration for scope '${policy.scope}'.";
  cellFor = stage: policy: let
    declaration =
      if policy.status == "qualified"
      then selectDeclaration stage policy
      else null;
  in {
    id =
      if declaration == null
      then "unassigned/${stage}"
      else "${declaration.adapter}/${stage}";
    inherit (policy) blockers evidence status;
    inherit stage;
    interface_descriptor =
      if declaration == null
      then null
      else declaration.interface.descriptor;
    interface_name =
      if declaration == null
      then null
      else declaration.interface.name;
    required_guarantees =
      if declaration == null
      then []
      else declaration.guarantees;
    strategy =
      if declaration == null
      then null
      else declaration.adapter;
  };
  cells = lib.mapAttrsToList cellFor stagePolicy;
  missingCells = builtins.filter (cell: cell.status == "missing") cells;
  surface = {
    schema = "aos.qualification.container-execution-surface/v1";
    inherit cells;
  };
  surfaceDigest = builtins.hashString "sha256" (builtins.toJSON surface);
in {
  inherit cells;
  check = "container-execution-surface-v1-sha256-${surfaceDigest}";
  missing_container_cells = builtins.length missingCells;
}
