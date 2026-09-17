##! Pure controller composition for transaction-scoped boot preparations.
{
  config,
  lib,
  ...
}: let
  interface = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
  terminalDeclaration = config.aos.abilities.interfaces.boot-preparation-command;
  terminalInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration terminalDeclaration
  );
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  bindingFor = bindings: requestName: let
    matches =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a boot-preparation request must have exactly one selected binding";
  resourceReference = instance: key: {
    interface = interface.identity;
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = ["observe"];
    lifetime = "transaction";
  };
  provide = {
    instance,
    requests,
    bindings,
    ...
  }: let
    entries = builtins.map (requestName: {
      inherit requestName;
      request = requests.${requestName};
      binding = bindingFor bindings requestName;
    }) (builtins.attrNames requests);
  in
    emptyProvision
    // {
      requests = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            requirement = "command";
            scope = [entry.binding.slot];
            slot = entry.binding.slot;
            parameters = entry.request.parameters;
          };
        })
        entries);
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = resourceReference instance entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = interface.name;
            lifetime = "transaction";
            value = entry.request.parameters;
          };
        })
        entries);
    };
  compose = {resources, ...}: {
    requests = {};
    outputs = {};
    realizations =
      builtins.mapAttrs (_: _: {
        schema = "aos.boot.preparation-realization/v1";
      })
      resources;
  };

  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };
  transition = context: let
    changed =
      builtins.filter
      (change:
        change.resource.provider
        == context.provider
        && builtins.elem change.kind [
          "create"
          "update"
          "reconcile-stopped"
          "reconcile-divergent"
        ])
      context.changes;
    desiredResource = change: let
      matches =
        builtins.filter
        (resource: resource.resource == change.resource)
        context.after.resources;
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "boot preparation transition requires one exact desired resource for ${change.resource.key}";
    terminalBinding = change: let
      matches =
        builtins.filter
        (entry:
          entry.authority.role
          == "desired"
          && entry.binding.request.consumer == context.provider
          && entry.binding.request.key == change.resource.key
          && entry.binding.interface == terminalInterface
          && builtins.elem "prepare" entry.binding.caller_grant.methods
          && builtins.length (builtins.filter
            (permission:
              permission.resource
              == change.resource
              && permission.access == "exclusive-write"
              && builtins.elem "prepare" permission.operations)
            entry.binding.caller_grant.resources)
          == 1)
        context.authorized_bindings;
    in
      if builtins.length matches == 1
      then (builtins.head matches).binding
      else throw "boot preparation transition requires one authorized command binding for ${change.resource.key}";
    controllerFor = resource: let
      matches =
        builtins.filter
        (entry: entry.resource == resource)
        context.controllers;
    in
      if builtins.length matches == 1
      then (builtins.head matches).controller
      else throw "boot preparation transition requires one controller for ${resource.key}";
    operation = change: let
      desired = desiredResource change;
      terminal = terminalBinding change;
    in {
      key = {
        scope = context.operation_scope;
        key = "prepare-${change.resource.key}";
      };
      branch_context = [];
      binding = terminal.id;
      authority = "caller";
      interface = terminal.interface;
      method = "prepare";
      phase = "preparing";
      input_phase = "planning";
      target = {
        interface = interface.identity;
        resource = change.resource;
        operations = ["prepare"];
        lifetime = "transaction";
      };
      inputs = {
        source = "literal";
        value = desired.value;
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
          interface = terminal.interface;
          method = "prepare";
        };
        cancel = {
          interface = terminal.interface;
          method = "prepare";
        };
        compensate = null;
      };
    };
  in
    lib.abilities.transitionFragment {
      operations = builtins.map operation changed;
    };
in {
  config.aos.abilities.implementations.boot-preparation = {
    inherit provide compose transition;
  };
}
