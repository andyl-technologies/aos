##! Adds qualification-only same-method dependencies to real provider effects.
{lib}: transition: context: let
  fragment = transition context;
  operationGroup = operation:
    builtins.toJSON {
      inherit (operation) interface method;
    };
  grouped =
    builtins.foldl' (
      groups: operation: let
        group = operationGroup operation;
      in
        groups
        // {
          ${group} = (groups.${group} or []) ++ [operation];
        }
    ) {}
    fragment.operations;
  pair = operations: let
    ordered = builtins.sort (left: right: left.key.key < right.key.key) operations;
  in
    lib.concatLists (lib.imap (index: operation:
      lib.optional (index + 1 < builtins.length ordered) {
        from = {
          kind = "operation";
          key = operation.key;
        };
        to = {
          kind = "operation";
          key = (builtins.elemAt ordered (index + 1)).key;
        };
        kind = "required-success";
      })
    ordered);
  pairedEdges = lib.concatMap pair (builtins.attrValues grouped);
  observationMethods = [
    "acquire"
    "observe"
    "observe-boot"
    "observe-health"
    "observe-manager"
    "read"
  ];
  mutationOperations =
    builtins.filter (
      operation: !builtins.elem operation.method observationMethods
    )
    fragment.operations;
  downstreamWitness = operations: let
    ordered = builtins.sort (left: right: left.key.key < right.key.key) operations;
    dependent = builtins.elemAt ordered 1;
    pairResources = map (operation: operation.target.resource) (
      lib.take 2 ordered
    );
    candidates =
      builtins.filter (
        operation: !builtins.elem operation.target.resource pairResources
      )
      mutationOperations;
    witness = builtins.head candidates;
  in
    lib.optional (
      builtins.length ordered
      >= 2
      && builtins.elem dependent.method observationMethods
      && dependent.method != "acquire"
      && candidates != []
    ) {
      from = {
        kind = "operation";
        key = dependent.key;
      };
      to = {
        kind = "operation";
        key = witness.key;
      };
      kind = "required-success";
    };
  downstreamWitnessEdges = lib.concatMap downstreamWitness (builtins.attrValues grouped);
  credentialWitness = operations: let
    ordered = builtins.sort (left: right: left.key.key < right.key.key) operations;
    dependent = builtins.elemAt ordered 1;
    recovery = dependent.recovery;
    routeFor = route:
      if route == null
      then null
      else route // {method = "deliver";};
  in
    lib.optionalAttrs (
      builtins.length ordered
      >= 2
      && dependent.interface.name == "aos.credential-delivery-effects"
      && dependent.method == "acquire"
    ) {
      operation =
        dependent
        // {
          key = dependent.key // {key = "matrix-witness-${dependent.key.key}";};
          method = "deliver";
          family = {
            kind = "credential";
            action = "deliver";
          };
          target = dependent.target // {operations = ["deliver"];};
          accesses = map (access: access // {mode = "exclusive-write";}) dependent.accesses;
          recovery =
            recovery
            // {
              reconcile = routeFor recovery.reconcile;
              cancel = routeFor recovery.cancel;
            };
        };
      edge = {
        from = {
          kind = "operation";
          key = dependent.key;
        };
        to = {
          kind = "operation";
          key = dependent.key // {key = "matrix-witness-${dependent.key.key}";};
        };
        kind = "required-success";
      };
    };
  credentialWitnesses = builtins.filter (witness: witness != {}) (
    map credentialWitness (builtins.attrValues grouped)
  );
  edgeKey = edge: builtins.toJSON edge;
  edgesByKey = builtins.listToAttrs (map (edge: {
      name = edgeKey edge;
      value = edge;
    }) (
      fragment.edges
      ++ pairedEdges
      ++ downstreamWitnessEdges
      ++ map (witness: witness.edge) credentialWitnesses
    ));
in
  fragment
  // {
    operations = builtins.sort (
      left: right: left.key.key < right.key.key
    ) (fragment.operations ++ map (witness: witness.operation) credentialWitnesses);
    edges = builtins.attrValues edgesByKey;
  }
