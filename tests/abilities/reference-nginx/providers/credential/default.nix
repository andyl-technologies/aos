##! Pure credential-delivery provider for the checked source fixture.
let
  effectsInterface = {
    name = "aos.credential-delivery-effects";
    abi = 1;
    descriptor = "sha256:bc251c0837c1d453a6c5840d9146d9e27a95ad82032d9b4c60baf40d293cf1eb";
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
      methods = ["acquire" "deliver" "release"];
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
    incomingBindings =
      builtins.filter
      (binding:
        binding.provider
        == context.provider
        && binding.provider_grant.principal == context.provider)
      context.after.bindings;
    consumerResources =
      builtins.concatMap
      (binding:
        builtins.map
        (permission: permission.resource)
        (builtins.filter
          (permission:
            permission.resource.provider
            != context.provider
            && permission.access == "read")
          binding.provider_grant.resources))
      incomingBindings;
    consumerTransition =
      builtins.any
      (change:
        builtins.elem change.resource consumerResources
        && builtins.elem change.kind [
          "create"
          "update"
          "remove"
          "reconcile-stopped"
          "reconcile-divergent"
        ])
      context.changes;
    unchanged =
      if consumerTransition
      then
        builtins.filter
        (change:
          change.resource.provider
          == context.provider
          && change.kind == "unchanged")
        context.changes
      else [];
    removed =
      builtins.filter
      (change:
        change.resource.provider
        == context.provider
        && change.kind == "remove")
      context.changes;
    terminalFor = authorityRole: change: method: access: let
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
              && (
                permission.access
                == access
                || (access == "read" && permission.access == "exclusive-write")
              )
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
    operation = authorityRole: change: method: family: phase: access: let
      terminal = terminalFor authorityRole change method access;
      version =
        if authorityRole == "teardown"
        then change.current
        else change.desired;
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
        value = {
          inherit version;
          view = change.resource.key;
        };
      };
      preconditions = [];
      accesses = [
        {
          resource = change.resource;
          mode = access;
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
        } "preparing" "exclusive-write")
      changed;
    observes =
      builtins.map
      (change:
        operation "desired" change "acquire" {
          kind = "credential";
          action = "acquire";
        } "preparing" "read")
      unchanged;
    releases =
      builtins.map
      (change: operation "teardown" change "release" {kind = "release-resource";} "converging" "exclusive-write")
      removed;
    viewExports =
      builtins.map
      (entry: {
        key = "view-${entry.change.resource.key}";
        kind = "completion";
        node = node "${entry.method}-${entry.change.resource.key}";
        outputs.credential-view = {
          producer = node "${entry.method}-${entry.change.resource.key}";
          output = "credential-view";
        };
      })
      (
        (builtins.map (change: {
            inherit change;
            method = "deliver";
          })
          changed)
        ++ (builtins.map (change: {
            inherit change;
            method = "acquire";
          })
          unchanged)
      );
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
        (deliveries ++ observes ++ releases);
      decisions = [];
      merges = [];
      edges = [];
      exports =
        builtins.sort
        (left: right: left.key < right.key)
        (viewExports ++ releaseExports);
      imports = [];
      links = [];
      handoffs = [];
      provider_readiness = [];
      obligations = [];
    };
  in
    if changed == [] && unchanged == [] && removed == []
    then
      fragment
      // {
        operations = [];
        exports = [];
      }
    else fragment;
}
