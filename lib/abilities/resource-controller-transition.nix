##! Builds a controller transition over one exact outgoing terminal binding.
##!
##! Packages choose every lifecycle method explicitly. This helper only
##! applies the common authority, resource-grant, controller, and graph-shape
##! checks needed by single-resource terminal controllers.
{
  transitionFragment,
  context,
  terminalInterface,
  actions,
  attemptTimeoutMillis ? 120000,
  totalRecoveryMillis ? 480000,
}: let
  changeKinds = [
    "create"
    "reconcile-divergent"
    "reconcile-stopped"
    "remove"
    "unchanged"
    "update"
  ];
  invalidActionKinds = builtins.filter (
    kind: !(builtins.elem kind changeKinds)
  ) (builtins.attrNames actions);
  missingActionKinds =
    builtins.filter (
      kind: !(builtins.hasAttr kind actions)
    )
    changeKinds;
  checkedActions =
    if invalidActionKinds != [] || missingActionKinds != []
    then throw "resource controller transition must classify every canonical change kind exactly once"
    else actions;
  actionFor = change:
    if change.kind == "retain-persistent"
    then null
    else if builtins.hasAttr change.kind checkedActions
    then checkedActions.${change.kind}
    else throw "resource controller transition received an unsupported change kind";
  stateFor = change: let
    snapshot =
      if change.kind == "remove"
      then context.before
      else context.after;
    resources =
      if snapshot == null
      then []
      else snapshot.resources;
    matches = builtins.filter (state: state.resource == change.resource) resources;
  in
    if builtins.length matches > 1
    then throw "resource controller transition found duplicate exact resource state"
    else if matches == []
    then null
    else builtins.head matches;
  activeChanges = builtins.filter (change: let
    state = stateFor change;
  in
    change.resource.provider
    == context.provider
    && state != null
    && state.kind == context.interface.name
    && actionFor change != null)
  context.changes;

  authorityRoleFor = change:
    if change.kind == "remove"
    then "teardown"
    else "desired";
  authorityMatches = role: entry:
    entry.authority.role
    == role
    && (
      if role == "desired"
      then entry.binding.request.consumer == context.provider
      else entry.authority.source_request.consumer == context.provider
    );
  terminalFor = change: action: let
    role = authorityRoleFor change;
    selected =
      builtins.filter (
        entry:
          authorityMatches role entry
          && entry.binding.interface == terminalInterface
          && builtins.elem action.method entry.binding.caller_grant.methods
          && builtins.length (
            builtins.filter (
              permission:
                permission.resource
                == change.resource
                && permission.access == action.access
                && builtins.elem action.method permission.operations
            )
            entry.binding.caller_grant.resources
          )
          == 1
      )
      context.authorized_bindings;
  in
    if builtins.length selected == 1
    then (builtins.head selected).binding
    else
      throw
      "resource controller transition requires one authorized ${role} terminal binding for ${action.method} on ${change.resource.key}";
  controllerFor = resource: let
    selected =
      builtins.filter (
        entry: entry.resource == resource
      )
      context.controllers;
  in
    if builtins.length selected == 1
    then (builtins.head selected).controller
    else throw "resource controller transition requires one exact lifecycle controller";
  scopedKey = key: {
    scope = context.operation_scope;
    inherit key;
  };
  operationFor = change: let
    action = actionFor change;
    terminal = terminalFor change action;
    state = stateFor change;
  in {
    key = scopedKey "${action.method}-${change.resource.key}";
    branch_context = [];
    binding = terminal.id;
    authority = "caller";
    interface = terminal.interface;
    inherit (action) method phase;
    input_phase = "planning";
    target = {
      interface = context.interface;
      resource = change.resource;
      operations = [action.method];
      lifetime = state.lifetime;
    };
    inputs = {
      source = "literal";
      value = state.value;
    };
    preconditions = [];
    accesses = [
      {
        resource = change.resource;
        mode = action.access;
      }
    ];
    controller = controllerFor change.resource;
    deadline = {
      attempt_timeout_millis = attemptTimeoutMillis;
      total_recovery_millis = totalRecoveryMillis;
    };
    recovery = {
      retry = {
        kind = "bounded";
        max_attempts = 2;
        backoff_millis = 0;
      };
      reconcile = {
        interface = terminal.interface;
        method = action.method;
      };
      cancel = null;
      compensate = null;
    };
  };
  operationLessThan = left: right: left.key.key < right.key.key;
in
  transitionFragment {
    operations = builtins.sort operationLessThan (builtins.map operationFor activeChanges);
  }
