##! Adds real-handler settlement witnesses for effect-boundary qualification.
{lib}: transition: context: let
  original = transition context;
  withRecovery = operation:
    operation
    // {
      recovery =
        operation.recovery
        // {
          reconcile =
            if operation.recovery.reconcile == null
            then {
              inherit (operation) interface method;
            }
            else operation.recovery.reconcile;
        };
    };
  fragment = original // {operations = map withRecovery original.operations;};
  operationNode = operation: {
    kind = "operation";
    key = operation.key;
  };
  hasRequiredSuccessor = operation:
    builtins.any (
      edge:
        edge.kind == "required-success"
        && edge.from == operationNode operation
        && edge.to.kind == "operation"
    )
    fragment.edges;
  operationsNeedingWitness = builtins.filter (
    operation: !hasRequiredSuccessor operation
  ) fragment.operations;
  witnessFor = operation: let
    witness = operation // {
      key = operation.key // {key = "effect-witness-${operation.key.key}";};
    };
  in {
    inherit witness;
    edge = {
      from = operationNode operation;
      to = operationNode witness;
      kind = "required-success";
    };
  };
  witnesses = map witnessFor operationsNeedingWitness;
  edgeKey = edge: builtins.toJSON edge;
  edgesByKey = builtins.listToAttrs (map (edge: {
      name = edgeKey edge;
      value = edge;
    }) (fragment.edges ++ map (entry: entry.edge) witnesses));
in
  fragment
  // {
    operations = builtins.sort (
      left: right: left.key.key < right.key.key
    ) (fragment.operations ++ map (entry: entry.witness) witnesses);
    edges = builtins.attrValues edgesByKey;
  }
