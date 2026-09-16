##! Pure ownership controller for persistent content-addressed objects.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "content-addressed-object";
  interface = lib.abilities.interfaces.contentAddressedArtifacts;
  controller = config.aos.abilities.implementations."${packageName}:${alias}";
  effectsInterface = builtins.head controller.requirements.effects.accepted_interfaces;

  emptyResult = {
    requests = {};
    outputs = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a content-addressed-object request must have exactly one selected binding";
  objectReference = instance: key: {
    interface = interface.identity;
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = ["observe" "remove"];
    lifetime = "persistent";
  };
  provide = {
    instance,
    requests,
    bindings,
    ...
  }: let
    entries = builtins.map (requestName: let
      binding = bindingFor bindings requestName;
    in {
      inherit requestName binding;
      parameters = requests.${requestName}.parameters;
    }) (builtins.attrNames requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.object-resource = objectReference instance entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = interface.identity.name;
            lifetime = "persistent";
            value = entry.parameters;
          };
        })
        entries);
    };
  compose = {resources, ...}:
    emptyResult
    // {
      requests =
        builtins.mapAttrs (key: resource: {
          requirement = "effects";
          scope = [key];
          slot = key;
          parameters = resource.value;
        })
        resources;
      realizations =
        builtins.mapAttrs (_: _: {
          schema = "aos.artifact.content-addressed-object-realization/v1";
        })
        resources;
    };

  emptyTransition = {
    schema = "aos.ability.transition-fragment/v1";
    operations = [];
    decisions = [];
    merges = [];
    edges = [];
    exports = [];
    imports = [];
    links = [];
    handoffs = [];
    provider_readiness = [];
    obligations = [];
  };
  revisionFor = context: change: let
    revisions =
      if change.desired != null
      then context.after.resources
      else if context.before == null
      then []
      else context.before.resources;
    matches = builtins.filter (revision: revision.resource == change.resource) revisions;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "content-object transition has no exact resource revision";
  controllerFor = context: resource: let
    matches = builtins.filter (entry: entry.resource == resource) context.controllers;
  in
    if builtins.length matches == 1
    then (builtins.head matches).controller
    else throw "content-object transition has no exact lifecycle controller";
  authorityRoleFor = change:
    if change.kind == "remove"
    then "teardown"
    else "desired";
  terminalBinding = context: change: method: access: let
    role = authorityRoleFor change;
    matches = builtins.filter (entry:
      entry.authority.role
      == role
      && (
        if role == "desired"
        then entry.binding.request.consumer == context.provider
        else entry.authority.source_request.consumer == context.provider
      )
      && entry.binding.interface == effectsInterface
      && builtins.elem method entry.binding.caller_grant.methods
      && builtins.length (builtins.filter (permission:
        permission.resource
        == change.resource
        && permission.access == access
        && builtins.elem method permission.operations)
      entry.binding.caller_grant.resources)
      == 1)
    context.authorized_bindings;
  in
    if builtins.length matches == 1
    then (builtins.head matches).binding
    else throw "content-object transition requires one exact ${role} ${method} binding";
  operationFor = context: change: method: phase: access: let
    revision = revisionFor context change;
    binding = terminalBinding context change method access;
  in {
    key = {
      scope = context.operation_scope;
      key = "${method}-${change.resource.key}";
    };
    branch_context = [];
    inherit (binding) interface;
    inherit method phase;
    binding = binding.id;
    authority = "caller";
    input_phase = "planning";
    target = {
      interface = interface.identity;
      inherit (change) resource;
      operations = [method];
      lifetime = "persistent";
    };
    inputs = {
      source = "literal";
      value = {
        request = revision.value;
        blob = null;
      };
    };
    preconditions = [];
    accesses = [
      {
        resource = change.resource;
        mode = access;
      }
    ];
    controller = controllerFor context change.resource;
    deadline = {
      attempt_timeout_millis = 120000;
      total_recovery_millis = 480000;
    };
    recovery = {
      retry = {
        kind = "bounded";
        max_attempts = 2;
        backoff_millis = 0;
      };
      reconcile =
        if method == "observe"
        then null
        else {
          inherit (binding) interface;
          inherit method;
        };
      cancel = null;
      compensate = null;
    };
  };
  actionFor = kind:
    if kind == "remove"
    then {
      method = "remove";
      phase = "converging";
      access = "exclusive-write";
    }
    else if builtins.elem kind ["reconcile-stopped" "reconcile-divergent"]
    then {
      method = "observe";
      phase = "recovering";
      access = "read";
    }
    else null;
  transition = context:
    emptyTransition
    // {
      operations = builtins.concatMap (change: let
        action = actionFor change.kind;
      in
        if action == null
        then []
        else [(operationFor context change action.method action.phase action.access)])
      context.changes;
    };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide compose transition;};
}
