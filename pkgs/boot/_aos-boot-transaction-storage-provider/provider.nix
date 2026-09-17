##! Pure controller for the ESP-backed initrd transaction-storage view.
{
  config,
  lib,
  ...
}: let
  alias = "boot-transaction-storage-view";
  interface = config.aos.abilities.interfaces.${alias};
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration interface
  );
  effects = config.aos.abilities.interfaces.boot-transaction-storage-view-effects;
  effectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration effects
  );
  transactionStoragePath = "/run/aos-boot-transaction-storage/aos/initrd-stage-journal";
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  emptyComposition = {
    requests = {};
    outputs = {};
    realizations = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "boot transaction storage requires one selected binding";
  resourceReference = instance: key: {
    interface = identity;
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
    entries = builtins.map (requestName: let
      binding = bindingFor bindings requestName;
    in {
      inherit requestName binding;
      parameters = requests.${requestName}.parameters;
      reference = resourceReference instance binding.slot;
    }) (builtins.attrNames requests);
  in
    emptyProvision
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value = {
            storage-path = transactionStoragePath;
            storage-resource = entry.reference;
          };
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = identity.name;
            lifetime = "transaction";
            value = entry.parameters;
          };
        })
        entries);
    };
  compose = {resources, ...}:
    emptyComposition
    // {
      requests =
        builtins.mapAttrs (key: resource: {
          requirement = "effects";
          scope = [key "effects"];
          slot = key;
          parameters = resource.value;
        })
        resources;
      realizations =
        builtins.mapAttrs (_: _: {
          schema = "aos.boot.transaction-storage-realization/v1";
          path = transactionStoragePath;
        })
        resources;
    };
  transition = context: let
    changed =
      builtins.filter (
        change:
          change.resource.provider
          == context.provider
          && builtins.elem change.kind ["create" "update" "reconcile-stopped" "reconcile-divergent"]
      )
      context.changes;
    desiredFor = change: let
      matches = builtins.filter (resource: resource.resource == change.resource) context.after.resources;
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "boot transaction storage requires one desired revision";
    terminalFor = change: let
      matches =
        builtins.filter (
          entry:
            entry.authority.role
            == "desired"
            && entry.binding.request.consumer == context.provider
            && entry.binding.request.key == change.resource.key
            && entry.binding.interface == effectsIdentity
            && builtins.elem "materialize" entry.binding.caller_grant.methods
        )
        context.authorized_bindings;
    in
      if builtins.length matches == 1
      then (builtins.head matches).binding
      else throw "boot transaction storage requires one authorized terminal binding";
    controllerFor = resource: let
      matches = builtins.filter (entry: entry.resource == resource) context.controllers;
    in
      if builtins.length matches == 1
      then (builtins.head matches).controller
      else throw "boot transaction storage requires one lifecycle controller";
    operation = change: let
      desired = desiredFor change;
      terminal = terminalFor change;
    in {
      key = {
        scope = context.operation_scope;
        key = "materialize-${change.resource.key}";
      };
      branch_context = [];
      binding = terminal.id;
      authority = "caller";
      interface = terminal.interface;
      method = "materialize";
      phase = "preparing";
      input_phase = "planning";
      target = {
        interface = identity;
        resource = change.resource;
        operations = ["materialize"];
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
      deadline = {
        attempt_timeout_millis = 30000;
        total_recovery_millis = 120000;
      };
      recovery = {
        retry = {
          kind = "bounded";
          max_attempts = 1;
          backoff_millis = 0;
        };
        reconcile = {
          interface = terminal.interface;
          method = "materialize";
        };
        cancel = null;
        compensate = null;
      };
    };
  in
    lib.abilities.transitionFragment {
      operations = builtins.map operation changed;
    };
in {
  config.aos.abilities.implementations.${alias} = {
    inherit provide compose transition;
  };
}
