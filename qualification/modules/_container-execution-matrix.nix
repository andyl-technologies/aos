##! Resolves execution-stage policy against selected package declarations.
{
  lib,
  nativeAdapterMatrix,
  stagePolicy,
}: let
  declarations = nativeAdapterMatrix.container_execution_declarations;
  selectDeclaration = stage: policy: let
    matches = builtins.filter (declaration: declaration.operation == policy.operation) declarations;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "Container execution stage '${stage}' must resolve exactly one selected package declaration for its native operation.";
  cellFor = stage: policy: let
    declaration = selectDeclaration stage policy;
  in {
    id = "${declaration.adapter}/${stage}";
    inherit (policy) blockers evidence status;
    inherit stage;
    inherit (declaration) operation handler actions;
    strategy = declaration.adapter;
  };
  cells = lib.mapAttrsToList cellFor stagePolicy;
  surface = {
    schema = "aos.qualification.container-execution-surface";
    inherit cells;
  };
  surfaceDigest = builtins.hashString "sha256" (builtins.toJSON surface);
in {
  inherit cells;
  check = "container-execution-surface-sha256-${surfaceDigest}";
}
