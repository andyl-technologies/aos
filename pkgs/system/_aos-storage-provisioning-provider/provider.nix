##! Pure storage-provisioning controller composition.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "storage-provisioning";
  interface = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  controller = config.aos.abilities.implementations."${packageName}:${alias}";
  terminalInterface = builtins.head controller.requirements.effects.accepted_interfaces;
  emptyResult = {
    requests = {};
    outputs = {};
  };
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a storage-provisioning request must have exactly one selected binding";
  reference = instance: key: {
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
      binding = bindingFor bindings requestName;
      parameters = requests.${requestName}.parameters;
    }) (builtins.attrNames requests);
  in
    emptyResult
    // {
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.readiness-resource = reference instance entry.binding.slot;
        })
        entries);
      resourceFragments = builtins.listToAttrs (builtins.map (entry: {
          name = entry.binding.slot;
          value = {
            kind = interface.identity.name;
            lifetime = "transaction";
            value = entry.parameters;
          };
        })
        entries);
    };
  executable = package: entry_point: {
    artifact = lib.abilities.packageOutput {inherit package;};
    inherit entry_point;
    arguments = [];
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
          schema = "aos.storage.provisioning-realization/v1";
          systemd_repart = executable "systemd" "bin/systemd-repart";
          blkid = executable "util-linux" "sbin/blkid";
          lsblk = executable "util-linux" "bin/lsblk";
          sfdisk = executable "util-linux" "sbin/sfdisk";
          udevadm = executable "systemd" "bin/udevadm";
        })
        resources;
    };

  action = {
    method = "commit";
    phase = "provisioning";
    access = "exclusive-write";
  };
  transition = context: let
    activeChanges =
      builtins.filter (
        change:
          change.resource.provider
          == context.provider
          && builtins.elem change.kind ["create" "update" "reconcile-stopped" "reconcile-divergent"]
      )
      context.changes;
    terminalFor = change: let
      matches =
        builtins.filter (
          entry:
            entry.authority.role
            == "desired"
            && entry.binding.request.consumer == context.provider
            && entry.binding.interface == terminalInterface
            && builtins.elem action.method entry.binding.caller_grant.methods
            && builtins.length (builtins.filter (
                permission:
                  permission.resource
                  == change.resource
                  && permission.access == action.access
                  && builtins.elem action.method permission.operations
              )
              entry.binding.caller_grant.resources)
            == 1
        )
        context.authorized_bindings;
    in
      if builtins.length matches == 1
      then (builtins.head matches).binding
      else throw "storage provisioning requires one authorized terminal binding for ${change.resource.key}";
    controllerFor = resource: let
      matches = builtins.filter (entry: entry.resource == resource) context.controllers;
    in
      if builtins.length matches == 1
      then (builtins.head matches).controller
      else throw "storage provisioning requires one exact lifecycle controller";
    operationFor = change: let
      terminal = terminalFor change;
    in {
      key = {
        scope = context.operation_scope;
        key = "commit-${change.resource.key}";
      };
      branch_context = [];
      binding = terminal.id;
      authority = "caller";
      interface = terminal.interface;
      method = action.method;
      phase = action.phase;
      input_phase = "planning";
      target = {
        interface = interface.identity;
        resource = change.resource;
        operations = [action.method];
        lifetime = "transaction";
      };
      inputs = {
        source = "literal";
        value = true;
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
        attempt_timeout_millis = 300000;
        total_recovery_millis = 1200000;
      };
      recovery = {
        retry = {
          kind = "bounded";
          max_attempts = 1;
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
  in {
    schema = "aos.ability.transition-fragment/v1";
    operations = builtins.map operationFor activeChanges;
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
in {
  config.aos.abilities.implementations.${alias} = {inherit provide compose transition;};
}
