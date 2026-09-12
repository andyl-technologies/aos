##! Adds real Kubernetes observation operations to changed fixture objects.
{lib}: transition: context: let
  fragment = transition context;
  applies = builtins.filter (
    operation:
      operation.interface.name == "aos.kubernetes-object-effects"
      && operation.method == "apply"
  ) fragment.operations;
  observeFor = apply:
    apply
    // {
      key = apply.key // {key = "observe-${apply.target.resource.key}";};
      method = "observe";
      family = {
        kind = "kubernetes-object";
        action = "observe";
      };
      target = apply.target // {operations = ["observe"];};
      accesses = map (access: access // {mode = "read";}) apply.accesses;
      recovery = apply.recovery // {
        reconcile = {
          inherit (apply) interface;
          method = "observe";
        };
      };
    };
  observations = map observeFor applies;
  operationNode = operation: {
    kind = "operation";
    key = operation.key;
  };
  observeEdges = lib.zipListsWith (apply: observe: {
    from = operationNode observe;
    to = operationNode apply;
    kind = "required-success";
  }) applies observations;
  readiness = builtins.filter (
    operation:
      operation.interface.name == "aos.systemd-provider-bootstrap"
      && operation.method == "observe-manager"
  ) fragment.operations;
  readinessEdges = lib.concatMap (ready:
    lib.concatMap (pair: [
      {
        from = operationNode ready;
        to = operationNode pair.observe;
        kind = "readiness";
      }
      {
        from = operationNode ready;
        to = operationNode pair.apply;
        kind = "required-success";
      }
    ]) (lib.zipListsWith (apply: observe: {inherit apply observe;}) applies observations))
  readiness;
in
  fragment
  // {
    operations = fragment.operations ++ observations;
    edges = fragment.edges ++ observeEdges ++ readinessEdges;
  }
