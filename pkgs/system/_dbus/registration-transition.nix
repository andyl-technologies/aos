##! Pure transition from a D-Bus registration aggregate to its configuration child.
{
  configurationInterface,
  registrationResourceKind,
  transitionFragment,
}: context: let
  deadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };
  matchesRegistration = change: let
    snapshot =
      if change.kind == "remove"
      then context.before
      else context.after;
  in
    snapshot
    != null
    && builtins.any (resource:
      resource.resource == change.resource && resource.kind == registrationResourceKind)
    snapshot.resources;
  actionable = builtins.filter (change:
    change.resource.provider
    == context.provider
    && matchesRegistration change
    && builtins.elem change.kind [
      "create"
      "update"
      "remove"
      "reconcile-stopped"
      "reconcile-divergent"
    ])
  context.changes;
  authorityFor = change:
    if change.kind == "remove"
    then "teardown"
    else "desired";
  snapshotFor = change:
    if change.kind == "remove"
    then context.before
    else context.after;
  childFor = change: interface: method: let
    authorityRole = authorityFor change;
    candidates = builtins.concatMap (entry:
      if
        entry.authority.role
        != authorityRole
        || entry.binding.interface != interface
        || !(builtins.elem method entry.binding.caller_grant.methods)
      then []
      else
        builtins.map (permission: {
          inherit entry permission;
        }) (builtins.filter (permission:
          permission.access
          == "exclusive-write"
          && builtins.elem method permission.operations)
        entry.binding.caller_grant.resources))
    context.authorized_bindings;
    selected =
      if builtins.length candidates == 1
      then builtins.head candidates
      else throw "D-Bus registration transition requires one authorized ${authorityRole} configuration child";
    resources = builtins.filter (resource:
      resource.resource
      == selected.permission.resource
      && resource.kind == interface.name)
    (snapshotFor change).resources;
  in
    if builtins.length resources == 1
    then selected // {resource = builtins.head resources;}
    else throw "D-Bus registration transition requires one exact configuration child resource";
  controllerFor = resource: let
    matches = builtins.filter (entry: entry.resource == resource) context.controllers;
  in
    if builtins.length matches == 1
    then (builtins.head matches).controller
    else throw "D-Bus registration transition requires one aggregate resource controller";
  scopedKey = key: {
    scope = context.operation_scope;
    inherit key;
  };
  operationFor = change: interface: method: let
    child = childFor change interface method;
  in {
    key = scopedKey "${method}-${child.resource.resource.key}";
    branch_context = [];
    binding = child.entry.binding.id;
    authority = "caller";
    interface = child.entry.binding.interface;
    inherit method;
    phase = "converging";
    input_phase = "planning";
    target = {
      interface = child.entry.binding.interface;
      resource = child.resource.resource;
      operations = [method];
      inherit (child.resource) lifetime;
    };
    inputs = {
      source = "literal";
      value = child.resource.value;
    };
    preconditions = [];
    accesses = [
      {
        resource = child.resource.resource;
        mode = "exclusive-write";
      }
    ];
    controller = controllerFor change.resource;
    inherit deadline;
    recovery = {
      retry = {
        kind = "bounded";
        max_attempts = 2;
        backoff_millis = 0;
      };
      reconcile = {
        interface = child.entry.binding.interface;
        method = "observe";
      };
      cancel = {
        interface = child.entry.binding.interface;
        method = "observe";
      };
      compensate = null;
    };
  };
  operationsFor = change:
    if change.kind == "remove"
    then [(operationFor change configurationInterface "release")]
    else [(operationFor change configurationInterface "materialize")];
  operations = builtins.concatMap operationsFor actionable;
in
  transitionFragment {
    inherit operations;
  }
