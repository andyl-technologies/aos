##! Pure transition construction for the systemd service controller.
{
  effectsInterface,
  resourceInterface,
  transitionFragment,
}: context: let
  matchesResourceKind = import ./_systemd-transition-resource.nix "aos.service.instance" context;
  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };
  actionable = builtins.filter (change:
    change.resource.provider
    == context.provider
    && matchesResourceKind change
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
  referencedStateFor = snapshot: reference: let
    matches = builtins.filter (resource: resource.resource == reference.resource) snapshot.resources;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "systemd service prerequisite must resolve one exact resource state";
  bindingFor = change: method: let
    authorityRole = authorityFor change;
    matches = builtins.filter (entry:
      entry.authority.role
      == authorityRole
      && entry.binding.interface == effectsInterface
      && builtins.elem method entry.binding.caller_grant.methods
      && builtins.elem "observe" entry.binding.caller_grant.methods
      && builtins.length (builtins.filter (permission:
        permission.resource
        == change.resource
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
    prerequisiteReferences =
      (desired.value.dependencies.prerequisites or [])
      ++ (desired.realization.prerequisites or []);
    uniquePrerequisites = builtins.attrValues (builtins.listToAttrs (builtins.map (reference: {
        name = builtins.toJSON reference.resource;
        value = reference;
      })
      prerequisiteReferences));
    snapshot =
      if change.kind == "remove"
      then context.before
      else context.after;
    prerequisiteStates = builtins.map (referencedStateFor snapshot) uniquePrerequisites;
    resourceLessThan = left: right: builtins.toJSON left.resource < builtins.toJSON right.resource;
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
      interface = resourceInterface;
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
    preconditions = builtins.sort resourceLessThan (builtins.map (resource: {
        inherit (resource) resource;
        expected_revision = resource.revision;
        expected_incarnation = null;
      })
      prerequisiteStates);
    accesses = builtins.sort resourceLessThan (
      [
        {
          resource = change.resource;
          mode = "exclusive-write";
        }
      ]
      ++ builtins.map (resource: {
        inherit (resource) resource;
        mode = "read";
      })
      prerequisiteStates
    );
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
