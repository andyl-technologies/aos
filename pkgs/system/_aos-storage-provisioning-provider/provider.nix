##! Pure storage-provisioning controller composition.
{
  config,
  lib,
  ...
}: let
  alias = "storage-provisioning";
  interface = lib.abilities.interfaces.blockStorage.interfaces.provisioning;
  contentObject = lib.abilities.interfaces.contentAddressedArtifacts;
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
      requests =
        builtins.foldl' (
          requests: entry:
            requests
            // authorizedInputChildRequests entry.binding.slot entry.parameters
        ) {}
        entries;
      outputs = builtins.listToAttrs (builtins.map (entry: {
          name = entry.requestName;
          value.resource = reference instance entry.binding.slot;
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
  authorizedInputObject = key: parameters: {
    name = "authorized-provisioning-input-${key}";
    media_type = "application/vnd.aos.metadata.authorized-provisioning-input+json;version=1";
    prerequisites = parameters.prerequisites;
  };
  authorizedInputChildRequests = key: parameters: let
    objectKey = "authorized-provisioning-input-${key}";
    objectRequest = authorizedInputObject key parameters;
  in {
    "authorized-input-object-${key}" = {
      requirement = "authorized-input-object";
      scope = [key "authorized-input-object"];
      slot = objectKey;
      parameters = objectRequest;
    };
    "authorized-input-object-operations-${key}" = {
      requirement = "authorized-input-object-operations";
      scope = [key "authorized-input-object-operations"];
      slot = "${objectKey}-provisioning-operations";
      parameters = objectRequest;
    };
  };
  childRequests = key: resource: {
    "${key}" = childRequest "effects" key resource.value;
    "detect-platform-${key}" = childRequest "detect-platform" key resource.value;
    "acquire-metadata-${key}" = childRequest "acquire-metadata" key resource.value;
    "authorize-input-${key}" = childRequest "authorize-input" key resource.value;
    "observe-marker-${key}" = childRequest "observe-marker" key resource.value;
    "evaluate-configuration-${key}" = childRequest "evaluate-configuration" key resource.value;
    "package-store-read-view-${key}" = childRequest "package-store-read-view" key {
      scope = "boot-image";
    };
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
        builtins.mapAttrs (key: _: {
          schema = "aos.storage.provisioning-realization/v1";
          systemd_repart = executable "systemd" "bin/systemd-repart";
          blkid = executable "util-linux" "sbin/blkid";
          lsblk = executable "util-linux" "bin/lsblk";
          sfdisk = executable "util-linux" "sbin/sfdisk";
          udevadm = executable "systemd" "bin/udevadm";
          store_view = lib.abilities.resultOf "package-store-read-view-${key}" "locator";
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
    revisionForResource = resource: kind: let
      matches = builtins.filter (revision:
        revision.resource
        == resource
        && revision.kind == kind)
      context.after.resources;
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "storage provisioning requires one exact ${kind} revision";
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
      offlineAcquisitionKey = "acquire-offline-${resourceKey}";
      onlineAcquisitionKey = "acquire-online-${resourceKey}";
      acquisitionMergeKey = "acquired-metadata-${resourceKey}";
      authorizationKey = "authorize-${resourceKey}";
      markerKey = "observe-marker-${resourceKey}";
      evaluationKey = "evaluate-configuration-${resourceKey}";
      networkApplyKey = "apply-network-bootstrap-${resourceKey}";
      commitKey = "commit-${resourceKey}";
      authorizedInputCommitKey = "commit-authorized-input-${resourceKey}";
      detectBinding = selectedBinding change "detect-platform" "detect" "read";
      acquisitionBinding = selectedBinding change "acquire-metadata" "acquire" "exclusive-write";
      authorizationBinding = selectedBinding change "authorize-input" "authorize" "exclusive-write";
      markerBinding = selectedBinding change "observe-marker" "observe" "read";
      evaluationBinding = selectedBinding change "evaluate-configuration" "evaluate" "exclusive-write";
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
      contentOwnerEntry = selectedExternalBinding change "authorized-input-object" "observe" "read";
      contentOwnerBinding = contentOwnerEntry.binding;
      contentOwnerPermissions = builtins.filter (permission:
        permission.access
        == "read"
        && builtins.elem "observe" permission.operations)
      contentOwnerBinding.caller_grant.resources;
      contentResource =
        if
          contentOwnerBinding.interface
          == contentObject.identity
          && builtins.length contentOwnerPermissions == 1
        then (builtins.head contentOwnerPermissions).resource
        else throw "storage provisioning requires one exact authorized-input content owner";
      contentRevision = revisionForResource contentResource contentObject.identity.name;
      contentRequest = authorizedInputObject resourceKey desired.value;
      checkedContentRequest =
        if contentRevision.value == contentRequest
        then contentRevision.value
        else throw "storage provisioning authorized-input content request differs from its desired revision";
      contentOperationsEntry = selectedExternalBinding change "authorized-input-object-operations" "commit" "exclusive-write";
      contentOperationsBinding = contentOperationsEntry.binding;
      contentOperationsPermissions = builtins.filter (permission:
        permission.resource
        == contentResource
        && permission.access == "exclusive-write"
        && builtins.elem "commit" permission.operations)
      contentOperationsBinding.caller_grant.resources;
      checkedContentResource =
        if
          contentOperationsBinding.interface
          == contentObject.operationInterface.identity
          && builtins.length contentOperationsPermissions == 1
        then (builtins.head contentOperationsPermissions).resource
        else throw "storage provisioning requires one exact authorized-input content operation resource";
      hostNetworkRevisions = builtins.filter (revision:
        revision.resource
        == hostNetworkResource
        && revision.kind == networkConfiguration.identity.name)
      context.after.resources;
      hostNetworkRevision =
        if builtins.length hostNetworkRevisions == 1
        then builtins.head hostNetworkRevisions
        else throw "storage provisioning requires one exact persistent host-network revision";
      bootstrapInput =
        if hostNetworkRevision.value.authority == "operator"
        then literal null
        else result "merge" acquisitionMergeKey "network-bootstrap";
      bootstrapEdges =
        lib.optional
        (hostNetworkRevision.value.authority != "operator")
        (edge "merge" acquisitionMergeKey "operation" networkApplyKey "data");
      requestInput = literal desired.value;
      metadataInputs = extra: object ({request = requestInput;} // extra);
      authorizationInputs = metadataInputs {
        configuration = literal config.aos.metadata.storageProvisioning.authorizationConfiguration;
        acquired_metadata = result "merge" acquisitionMergeKey "acquired-metadata";
      };
      acquisitionInputs = metadataInputs {
        platform = result "operation" detectKey "platform";
        blkid = literal (executable "util-linux" "sbin/blkid");
        mount = literal (executable "util-linux" "bin/mount");
        umount = literal (executable "util-linux" "bin/umount");
      };
      markerInputs = metadataInputs {
        lsblk = literal (executable "util-linux" "bin/lsblk");
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
        inputs = metadataInputs {
          blkid = literal (executable "util-linux" "sbin/blkid");
          mount = literal (executable "util-linux" "bin/mount");
          umount = literal (executable "util-linux" "bin/umount");
        };
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
      acquire = key: alternative:
        operation {
          inherit key;
          branchContext = branch decisionKey alternative;
          binding = acquisitionBinding;
          method = "acquire";
          phase = "preparing";
          inputPhase = "runtime";
          targetInterface = interface.identity;
          targetResource = resource;
          targetLifetime = "transaction";
          inputs = acquisitionInputs;
          access = "exclusive-write";
          controller = controllerIdentity;
        };
      authorizationOperation = operation {
        key = authorizationKey;
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
      markerOperation = operation {
        key = markerKey;
        binding = markerBinding;
        method = "observe";
        phase = "preparing";
        inputPhase = "runtime";
        targetInterface = markerBinding.interface;
        targetResource = resource;
        targetLifetime = "transaction";
        inputs = markerInputs;
        access = "read";
        controller = controllerIdentity;
      };
      evaluationOperation = operation {
        key = evaluationKey;
        binding = evaluationBinding;
        method = "evaluate";
        phase = "preparing";
        inputPhase = "runtime";
        targetInterface = interface.identity;
        targetResource = resource;
        targetLifetime = "transaction";
        inputs = metadataInputs {
          authorized_input = object {
            kind = literal "direct-result";
            input = result "operation" authorizationKey "authorized-provisioning-input";
          };
          marker = result "operation" markerKey "marker";
          store_view = literal desired.realization.store_view;
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
        inputs = metadataInputs {plan = result "operation" evaluationKey "provisioning-plan";};
        access = "exclusive-write";
        controller = controllerIdentity;
      };
      authorizedInputCommitOperation = operation {
        key = authorizedInputCommitKey;
        binding = contentOperationsBinding;
        method = "commit";
        phase = "converging";
        inputPhase = "runtime";
        targetInterface = contentObject.identity;
        targetResource = checkedContentResource;
        targetLifetime = "persistent";
        inputs = object {
          request = literal checkedContentRequest;
          blob = result "operation" authorizationKey "authorized-input-blob";
        };
        access = "exclusive-write";
        controller = controllerFor contentResource;
      };
    in {
      operations = [
        detectOperation
        networkOperation
        (acquire offlineAcquisitionKey "offline")
        (acquire onlineAcquisitionKey "online")
        authorizationOperation
        markerOperation
        evaluationOperation
        networkApplyOperation
        authorizedInputCommitOperation
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
          key = scopedKey acquisitionMergeKey;
          decision = scopedKey decisionKey;
          branch_context = [];
          outputs = {
            acquired-metadata = {
              descriptor = methodOutput "aos.metadata.storage-provisioning-acquisition" "acquire" "acquired-metadata";
              alternatives = {
                offline = (result "operation" offlineAcquisitionKey "acquired-metadata").reference;
                online = (result "operation" onlineAcquisitionKey "acquired-metadata").reference;
              };
            };
            network-bootstrap = {
              descriptor = methodOutput "aos.metadata.storage-provisioning-acquisition" "acquire" "network-bootstrap";
              alternatives = {
                offline = (result "operation" offlineAcquisitionKey "network-bootstrap").reference;
                online = (result "operation" onlineAcquisitionKey "network-bootstrap").reference;
              };
            };
          };
        }
      ];
      edges =
        [
          (edge "operation" detectKey "decision" decisionKey "data")
          (edge "decision" decisionKey "operation" offlineAcquisitionKey "branch-guard")
          (edge "decision" decisionKey "operation" networkKey "branch-guard")
          (edge "decision" decisionKey "operation" onlineAcquisitionKey "branch-guard")
          (edge "operation" networkKey "operation" onlineAcquisitionKey "readiness")
          (edge "operation" offlineAcquisitionKey "merge" acquisitionMergeKey "branch-merge")
          (edge "operation" onlineAcquisitionKey "merge" acquisitionMergeKey "branch-merge")
          (edge "merge" acquisitionMergeKey "operation" authorizationKey "data")
          (edge "operation" authorizationKey "operation" evaluationKey "data")
          (edge "operation" markerKey "operation" evaluationKey "data")
          (edge "operation" authorizationKey "operation" authorizedInputCommitKey "data")
          (edge "operation" authorizedInputCommitKey "operation" commitKey "readiness")
          (edge "operation" evaluationKey "operation" commitKey "data")
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
