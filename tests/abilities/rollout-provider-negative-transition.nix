##! Adds one same-machine RequiredSuccess successor to a selected rollout method.
{
  lib,
  method,
  operationKey,
}: transition: context: let
  fragment = transition context;
  selected =
    builtins.filter (
      operation:
        operation.interface.name
        == "aos.ab-image-rollout-effects"
        && operation.method == method
        && operation.key.key == operationKey
    )
    fragment.operations;
in
  if selected == []
  then fragment
  else let
    primary =
      if builtins.length selected == 1
      then builtins.head selected
      else throw "rollout provider-negative transition selected multiple primary operations";
    dependent =
      primary
      // {
        key = primary.key // {key = "matrix-dependent-${primary.key.key}";};
      };
    holdOperations =
      builtins.filter (
        operation:
          operation.interface.name
          == "aos.ab-image-rollout-effects"
          && operation.method == "hold"
      )
      fragment.operations;
    witness =
      if builtins.elem method ["observe-boot" "observe-health"]
      then
        (builtins.head holdOperations)
        // {
          key = primary.key // {key = "matrix-observation-witness-${primary.key.key}";};
          branch_context = primary.branch_context;
        }
      else null;
    operationNode = operation: {
      kind = "operation";
      key = operation.key;
    };
  in
    fragment
    // {
      operations = fragment.operations ++ [dependent] ++ lib.optional (witness != null) witness;
      edges =
        fragment.edges
        ++ [
          {
            from = operationNode primary;
            to = operationNode dependent;
            kind = "required-success";
          }
        ]
        ++ lib.optional (witness != null) {
          from = operationNode dependent;
          to = operationNode witness;
          kind = "required-success";
        };
    }
