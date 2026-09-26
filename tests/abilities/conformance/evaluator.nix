##! Restricted evaluator for the shared portable-schema corpus.
let
  schemas = import ./schema.nix;
in {
  compose = arguments:
    schemas.checkValue arguments.case.schema arguments.case.value;
}
