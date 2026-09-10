##! Pure credential-delivery provider for the checked source fixture.
let
  effectsInterface = {
    name = "aos.credential-delivery-effects";
    abi = 1;
    descriptor = "sha256:a458175ca774c3fbe85172d79ec25255c560eed80846c42bf554767ea46ac222";
  };

  # Recovery retains time for an interrupted delivery, reconciliation, a
  # bounded retry, and a final observation of the selected credential view.
  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };

  compose = context: let
    credentialDelivery = context.interface;
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    resourceFor = contribution: {
      provider = context.provider;
      key = "${contribution.slot}-credential-view";
    };
    effectsRequest = {
      id = {
        consumer = context.provider;
        scope = [context.provider.key];
        key = "effects";
      };
      accepted_interfaces = [effectsInterface];
      methods = ["deliver" "release"];
      guarantees = [];
      lifetime = "instance";
    };
    fields = builtins.listToAttrs (
      builtins.map
      (contribution: {
        name = contribution.slot;
        value = {
          source = "resource-reference";
          reference = {
            interface = credentialDelivery;
            resource = resourceFor contribution;
            operations = ["deliver"];
            lifetime = "instance";
          };
        };
      })
      contributions
    );
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests = [effectsRequest];
    contributions = [];
    resources =
      builtins.map
      (contribution: {
        resource = resourceFor contribution;
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON contribution.value)}";
      })
      contributions;
    outputs = [
      {
        aggregate = {
          provider = context.provider;
          group = "credentials";
        };
        interface = credentialDelivery;
        port = "credential-views";
        value = {
          source = "object";
          inherit fields;
        };
      }
    ];
    controllers =
      builtins.map
      (contribution: {
        resource = resourceFor contribution;
        controller = {
          provider = context.provider;
          group = "credentials";
        };
      })
      contributions;
  };
in {
  inherit compose;

  transition = context: let
    changed =
      builtins.filter
      (change:
        change.resource.provider
        == context.provider
        && (change.kind == "create" || change.kind == "update"))
      context.changes;
    removed =
      builtins.filter
      (change:
        change.resource.provider
        == context.provider
        && change.kind == "remove")
      context.changes;
    terminalFor = authorityRole: change: method: let
      selected =
        builtins.filter
        (entry:
          entry.authority.role
          == authorityRole
          && (
            if authorityRole == "desired"
            then
              entry.binding.request.consumer
              == context.provider
              && entry.binding.request.key == "effects"
            else
              entry.authority.source_request.consumer
              == context.provider
              && entry.authority.source_request.key == "effects"
          )
          && entry.binding.interface == effectsInterface
          && builtins.elem method entry.binding.caller_grant.methods
          && builtins.length (
            builtins.filter
            (permission:
              permission.resource
              == change.resource
              && permission.access == "exclusive-write"
              && builtins.elem method permission.operations)
            entry.binding.caller_grant.resources
          )
          == 1)
        context.authorized_bindings;
    in
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "credential-delivery transition requires exactly one authorized ${authorityRole} effects binding for ${method} on ${change.resource.key}";
    scopedKey = name: {
      scope = context.operation_scope;
      key = name;
    };
    node = name: {
      kind = "operation";
      key = scopedKey name;
    };
    controllerFor = resource: let
      controllers = builtins.filter (entry: entry.resource == resource) context.controllers;
    in
      if builtins.length controllers == 1
      then (builtins.head controllers).controller
      else throw "credential-delivery transition requires one resource controller";
    operation = authorityRole: change: method: family: phase: let
      terminal = terminalFor authorityRole change method;
    in {
      key = scopedKey "${method}-${change.resource.key}";
      branch_context = [];
      binding = terminal.id;
      authority = "caller";
      interface = terminal.interface;
      inherit method family phase;
      input_phase = "planning";
      target = {
        interface = terminal.interface;
        resource = change.resource;
        operations = [method];
        lifetime = "instance";
      };
      inputs = {
        source = "literal";
        value = true;
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
          inherit method;
        };
        cancel = null;
        compensate = null;
      };
    };
    deliveries =
      builtins.map
      (change:
        operation "desired" change "deliver" {
          kind = "credential";
          action = "deliver";
        } "preparing")
      changed;
    releases =
      builtins.map
      (change: operation "teardown" change "release" {kind = "release-resource";} "converging")
      removed;
    deliveryExports =
      builtins.map
      (change: {
        key = "delivered-${change.resource.key}";
        kind = "completion";
        node = node "deliver-${change.resource.key}";
        outputs = {};
      })
      changed;
    releaseExports =
      builtins.map
      (change: {
        key = "release-entry-${change.resource.key}";
        kind = "entry";
        node = node "release-${change.resource.key}";
        outputs = {};
      })
      removed;
    fragment = {
      schema = "aos.ability.transition-fragment/v1";
      operations =
        builtins.sort
        (left: right: left.key.key < right.key.key)
        (deliveries ++ releases);
      decisions = [];
      merges = [];
      edges = [];
      exports =
        builtins.sort
        (left: right: left.key < right.key)
        (deliveryExports ++ releaseExports);
      imports = [];
      links = [];
      handoffs = [];
      provider_readiness = [];
      obligations = [];
    };
  in
    if changed == [] && removed == []
    then
      fragment
      // {
        operations = [];
        exports = [];
      }
    else fragment;
}
