##! Pure transition construction for the systemd service controller.
{
  effectsInterface,
  transitionFragment,
}: context: let
  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };
  actionable = builtins.filter (change:
    change.resource.provider == context.provider
    && builtins.elem change.kind [
      "create"
      "update"
      "remove"
      "reconcile-stopped"
      "reconcile-divergent"
    ])
  context.changes;
  methodFor = kind:
    if kind == "create"
    then "create"
    else if kind == "update"
    then "update"
    else if kind == "remove"
    then "remove"
    else "reconcile";
  authorityFor = change:
    if change.kind == "remove"
    then "teardown"
    else "desired";
  stateFor = change: let
    snapshot =
      if change.kind == "remove"
      then context.before
      else context.after;
    matches = builtins.filter (resource: resource.resource == change.resource) snapshot.resources;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "systemd service transition requires one exact ${authorityFor change} resource state for '${change.resource.key}'";
  bindingFor = change: method: let
    authorityRole = authorityFor change;
    matches = builtins.filter (entry:
      entry.authority.role == authorityRole
      && entry.binding.interface == effectsInterface
      && builtins.elem method entry.binding.caller_grant.methods
      && builtins.elem "observe" entry.binding.caller_grant.methods
      && builtins.length (builtins.filter (permission:
        permission.resource == change.resource
        && permission.access == "exclusive-write"
        && builtins.elem method permission.operations)
      entry.binding.caller_grant.resources)
      == 1)
    context.authorized_bindings;
  in
    if builtins.length matches == 1
    then (builtins.head matches).binding
    else throw "systemd service transition requires one authorized ${authorityRole} effects binding for '${change.resource.key}'";
  controllerFor = resource: let
    matches = builtins.filter (entry: entry.resource == resource) context.controllers;
  in
    if builtins.length matches == 1
    then (builtins.head matches).controller
    else throw "systemd service transition requires one exact resource controller";
  scopedKey = key: {
    scope = context.operation_scope;
    inherit key;
  };
  operationFor = change: let
    method = methodFor change.kind;
    binding = bindingFor change method;
    desired = stateFor change;
  in {
    key = scopedKey "${method}-${change.resource.key}";
    branch_context = [];
    binding = binding.id;
    authority = "caller";
    interface = binding.interface;
    inherit method;
    phase = "converging";
    input_phase = "planning";
    target = {
      interface = binding.interface;
      resource = change.resource;
      operations = [method];
      inherit (desired) lifetime;
    };
    inputs = {
      source = "literal";
      value = {
        kind = "service";
        desired = desired.value;
      };
    };
    preconditions = [];
    accesses = [
      {
        resource = change.resource;
        mode = "exclusive-write";
      }
    ];
    controller = controllerFor change.resource;
    deadline = operationDeadline;
    recovery = {
      retry = {
        kind = "bounded";
        max_attempts = 2;
        backoff_millis = 0;
      };
      reconcile = {
        interface = binding.interface;
        method = "observe";
      };
      cancel = {
        interface = binding.interface;
        method = "observe";
      };
      compensate = null;
    };
  };
in
  transitionFragment {
    operations = builtins.map operationFor actionable;
  }
