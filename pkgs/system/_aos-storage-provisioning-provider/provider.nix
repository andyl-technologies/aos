##! Pure storage-provisioning controller composition.
{
  config,
  lib,
  ...
}: let
  alias = "storage-provisioning";
  interface = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  networkConfiguration = lib.abilities.interfaces.networkConfiguration.interface;
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
  childRequest = requirement: key: parameters: {
    inherit requirement parameters;
    scope = [key requirement];
    slot = key;
  };
  childRequests = key: resource: {
    "${key}" = childRequest "effects" key resource.value;
    "detect-platform-${key}" = childRequest "detect-platform" key resource.value;
    "authorize-input-${key}" = childRequest "authorize-input" key resource.value;
    "observe-plan-${key}" = childRequest "observe-plan" key resource.value;
    "network-readiness-${key}" = childRequest "network-readiness" key {
      scope = "configured-connectivity";
      address_families = ["ipv4" "ipv6"];
    };
    "network-configuration-effects-${key}" = {
      requirement = "network-configuration-effects";
      scope = [key "network-configuration-effects"];
      slot = "host-network";
      parameters = {};
    };
  };
  compose = {resources, ...}:
    emptyResult
    // {
      requests = builtins.foldl' (requests: key: requests // childRequests key resources.${key}) {} (builtins.attrNames resources);
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

  declarationFor = name: let
    matches = builtins.filter (declaration: declaration.name == name) (builtins.attrValues config.aos.abilities.interfaces);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "storage provisioning requires one ${name} declaration";
  methodOutput = interfaceName: method: output: let
    descriptor = (declarationFor interfaceName).methods.${method}.outputs.${output};
  in {
    inherit (descriptor) schema phase visibility lifetime;
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
    revisionFor = change: let
      matches = builtins.filter (revision: revision.resource == change.resource) context.after.resources;
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "storage provisioning requires one exact desired revision for ${change.resource.key}";
    selectedBinding = change: requestPrefix: method: access: let
      requestKey =
        if requestPrefix == ""
        then change.resource.key
        else "${requestPrefix}-${change.resource.key}";
      matches =
        builtins.filter (
          entry:
            entry.authority.role
            == "desired"
            && entry.binding.request.consumer == context.provider
            && entry.binding.request.key == requestKey
            && builtins.elem method entry.binding.caller_grant.methods
            && builtins.length (builtins.filter (
                permission:
                  permission.resource
                  == change.resource
                  && permission.access == access
                  && builtins.elem method permission.operations
              )
              entry.binding.caller_grant.resources)
            == 1
        )
        context.authorized_bindings;
    in
      if builtins.length matches == 1
      then (builtins.head matches).binding
      else throw "storage provisioning requires one authorized ${requestKey} binding";
    selectedExternalBinding = change: requestPrefix: method: access: let
      requestKey = "${requestPrefix}-${change.resource.key}";
      matches = builtins.filter (entry:
        entry.authority.role
        == "desired"
        && entry.binding.request.consumer == context.provider
        && entry.binding.request.key == requestKey
        && builtins.elem method entry.binding.caller_grant.methods
        && builtins.length (builtins.filter (permission:
          permission.access
          == access
          && builtins.elem method permission.operations)
        entry.binding.caller_grant.resources)
        == 1)
      context.authorized_bindings;
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "storage provisioning requires one authorized ${requestKey} external binding";
    controllerFor = resource: let
      matches = builtins.filter (entry: entry.resource == resource) context.controllers;
    in
      if builtins.length matches == 1
      then (builtins.head matches).controller
      else throw "storage provisioning requires one exact lifecycle controller";
    scopedKey = key: {
      scope = context.operation_scope;
      inherit key;
    };
    node = kind: key: {
      inherit kind;
      key = scopedKey key;
    };
    result = kind: key: output: {
      source = "operation-result";
      reference = {
        producer = node kind key;
        inherit output;
      };
    };
    literal = value: {
      source = "literal";
      inherit value;
    };
    object = fields: {
      source = "object";
      inherit fields;
    };
    branch = decision: alternative: [
      {
        decision = scopedKey decision;
        inherit alternative;
      }
    ];
    recovery = binding: method: {
      retry = {
        kind = "bounded";
        max_attempts = 1;
        backoff_millis = 0;
      };
      reconcile = {
        inherit (binding) interface;
        inherit method;
      };
      cancel = null;
      compensate = null;
    };
    operation = {
      key,
      branchContext ? [],
      binding,
      method,
      phase,
      inputPhase,
      targetInterface,
      targetResource,
      targetLifetime,
      inputs,
      access,
      controller,
    }: {
      key = scopedKey key;
      branch_context = branchContext;
      binding = binding.id;
      authority = "caller";
      inherit (binding) interface;
      inherit method phase inputs controller;
      input_phase = inputPhase;
      target = {
        interface = targetInterface;
        resource = targetResource;
        operations = [method];
        lifetime = targetLifetime;
      };
      preconditions = [];
      accesses = [
        {
          resource = targetResource;
          mode = access;
        }
      ];
      deadline = {
        attempt_timeout_millis = 300000;
        total_recovery_millis = 1200000;
      };
      recovery = recovery binding method;
    };
    edge = fromKind: from: toKind: to: kind: {
      from = node fromKind from;
      to = node toKind to;
      inherit kind;
    };
    fragmentFor = change: let
      desired = revisionFor change;
      resource = change.resource;
      resourceKey = resource.key;
      controllerIdentity = controllerFor resource;
      detectKey = "detect-${resourceKey}";
      decisionKey = "network-decision-${resourceKey}";
      networkKey = "network-ready-${resourceKey}";
      offlineAuthorizationKey = "authorize-offline-${resourceKey}";
      onlineAuthorizationKey = "authorize-online-${resourceKey}";
      authorizationMergeKey = "authorized-input-${resourceKey}";
      planKey = "observe-plan-${resourceKey}";
      networkApplyKey = "apply-network-bootstrap-${resourceKey}";
      commitKey = "commit-${resourceKey}";
      detectBinding = selectedBinding change "detect-platform" "detect" "read";
      authorizationBinding = selectedBinding change "authorize-input" "authorize" "exclusive-write";
      planBinding = selectedBinding change "observe-plan" "observe" "exclusive-write";
      effectBinding = selectedBinding change "" "commit" "exclusive-write";
      networkEntry = selectedExternalBinding change "network-readiness" "observe" "read";
      networkBinding = networkEntry.binding;
      networkPermissions = builtins.filter (permission:
        permission.access
        == "read"
        && builtins.elem "observe" permission.operations)
      networkBinding.caller_grant.resources;
      networkResource = (builtins.head networkPermissions).resource;
      networkEffectsEntry = selectedExternalBinding change "network-configuration-effects" "apply" "exclusive-write";
      networkEffectsBinding = networkEffectsEntry.binding;
      networkEffectsPermissions = builtins.filter (permission:
        permission.access
        == "exclusive-write"
        && builtins.elem "apply" permission.operations)
      networkEffectsBinding.caller_grant.resources;
      hostNetworkResource = (builtins.head networkEffectsPermissions).resource;
      hostNetworkRevisions = builtins.filter (revision:
        revision.resource == hostNetworkResource
        && revision.kind == networkConfiguration.identity.name)
      context.after.resources;
      hostNetworkRevision =
        if builtins.length hostNetworkRevisions == 1
        then builtins.head hostNetworkRevisions
        else throw "storage provisioning requires one exact persistent host-network revision";
      bootstrapInput =
        if hostNetworkRevision.value.authority == "operator"
        then literal null
        else result "merge" authorizationMergeKey "network-bootstrap";
      bootstrapEdges =
        lib.optional
        (hostNetworkRevision.value.authority != "operator")
        (edge "merge" authorizationMergeKey "operation" networkApplyKey "data");
      requestInput = literal desired.value;
      metadataInputs = extra: object ({request = requestInput;} // extra);
      authorizationInputs = metadataInputs {
        configuration = literal config.aos.metadata.storageProvisioning.authorizationConfiguration;
        platform = result "operation" detectKey "platform";
      };
      detectOperation = operation {
        key = detectKey;
        binding = detectBinding;
        method = "detect";
        phase = "preparing";
        inputPhase = "planning";
        targetInterface = interface.identity;
        targetResource = resource;
        targetLifetime = "transaction";
        inputs = metadataInputs {};
        access = "read";
        controller = controllerIdentity;
      };
      networkOperation = operation {
        key = networkKey;
        branchContext = branch decisionKey "online";
        binding = networkBinding;
        method = "observe";
        phase = "preparing";
        inputPhase = "planning";
        targetInterface = networkBinding.interface;
        targetResource = networkResource;
        targetLifetime = "instance";
        inputs = literal {
          scope = "configured-connectivity";
          address_families = ["ipv4" "ipv6"];
        };
        access = "read";
        controller = controllerIdentity;
      };
      authorize = key: alternative:
        operation {
          inherit key;
          branchContext = branch decisionKey alternative;
          binding = authorizationBinding;
          method = "authorize";
          phase = "preparing";
          inputPhase = "runtime";
          targetInterface = interface.identity;
          targetResource = resource;
          targetLifetime = "transaction";
          inputs = authorizationInputs;
          access = "exclusive-write";
          controller = controllerIdentity;
        };
      planOperation = operation {
        key = planKey;
        binding = planBinding;
        method = "observe";
        phase = "preparing";
        inputPhase = "runtime";
        targetInterface = interface.identity;
        targetResource = resource;
        targetLifetime = "transaction";
        inputs = metadataInputs {
          authorized_input = result "merge" authorizationMergeKey "authorized-provisioning-input";
        };
        access = "exclusive-write";
        controller = controllerIdentity;
      };
      networkApplyOperation = operation {
        key = networkApplyKey;
        binding = networkEffectsBinding;
        method = "apply";
        phase = "converging";
        inputPhase = "runtime";
        targetInterface = networkConfiguration.identity;
        targetResource = hostNetworkResource;
        targetLifetime = "persistent";
        inputs = object {bootstrap = bootstrapInput;};
        access = "exclusive-write";
        controller = controllerIdentity;
      };
      commitOperation = operation {
        key = commitKey;
        binding = effectBinding;
        method = "commit";
        phase = "converging";
        inputPhase = "runtime";
        targetInterface = interface.identity;
        targetResource = resource;
        targetLifetime = "transaction";
        inputs = metadataInputs {plan = result "operation" planKey "provisioning-plan";};
        access = "exclusive-write";
        controller = controllerIdentity;
      };
    in {
      operations = [
        detectOperation
        networkOperation
        (authorize offlineAuthorizationKey "offline")
        (authorize onlineAuthorizationKey "online")
        planOperation
        networkApplyOperation
        commitOperation
      ];
      decisions = [
        {
          key = scopedKey decisionKey;
          branch_context = [];
          selector = {
            result = (result "operation" detectKey "need-network").reference;
            tag_field = null;
          };
          alternatives = [
            {
              key = "offline";
              predicate = {
                kind = "boolean";
                value = false;
              };
            }
            {
              key = "online";
              predicate = {
                kind = "boolean";
                value = true;
              };
            }
          ];
        }
      ];
      merges = [
        {
          key = scopedKey authorizationMergeKey;
          decision = scopedKey decisionKey;
          branch_context = [];
          outputs = {
            authorized-provisioning-input = {
              descriptor = methodOutput "aos.metadata.storage-provisioning-input-authorization" "authorize" "authorized-provisioning-input";
              alternatives = {
                offline = (result "operation" offlineAuthorizationKey "authorized-provisioning-input").reference;
                online = (result "operation" onlineAuthorizationKey "authorized-provisioning-input").reference;
              };
            };
            network-bootstrap = {
              descriptor = methodOutput "aos.metadata.storage-provisioning-input-authorization" "authorize" "network-bootstrap";
              alternatives = {
                offline = (result "operation" offlineAuthorizationKey "network-bootstrap").reference;
                online = (result "operation" onlineAuthorizationKey "network-bootstrap").reference;
              };
            };
          };
        }
      ];
      edges = [
        (edge "operation" detectKey "decision" decisionKey "data")
        (edge "decision" decisionKey "operation" offlineAuthorizationKey "branch-guard")
        (edge "decision" decisionKey "operation" networkKey "branch-guard")
        (edge "decision" decisionKey "operation" onlineAuthorizationKey "branch-guard")
        (edge "operation" networkKey "operation" onlineAuthorizationKey "readiness")
        (edge "operation" offlineAuthorizationKey "merge" authorizationMergeKey "branch-merge")
        (edge "operation" onlineAuthorizationKey "merge" authorizationMergeKey "branch-merge")
        (edge "merge" authorizationMergeKey "operation" planKey "data")
        (edge "operation" planKey "operation" commitKey "data")
      ]
      ++ bootstrapEdges;
    };
    fragments = builtins.map fragmentFor activeChanges;
  in
    lib.abilities.transitionFragment {
      operations = builtins.concatMap (fragment: fragment.operations) fragments;
      decisions = builtins.concatMap (fragment: fragment.decisions) fragments;
      merges = builtins.concatMap (fragment: fragment.merges) fragments;
      edges = builtins.concatMap (fragment: fragment.edges) fragments;
    };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide compose transition;};
}
