##! Pure managed-configuration provider for the checked source fixture.
let
  effectsInterface = {
    name = "aos.managed-configuration-effects";
    abi = 1;
    descriptor = "sha256:682ee08aadd9d0198b409146a373bf38d901ba530b74180400c9087616a41dab";
  };

  # Recovery conservatively charges a full interrupted call. Four call-sized
  # slices retain room for that attempt, reconciliation, a retry, and a final
  # reconciliation; one slice also spans a reference VM boot.
  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };

  compose = context: let
    managedConfiguration = context.interface;
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    resourceFor = contribution: {
      provider = context.provider;
      key = "${contribution.slot}-configuration";
    };
    quote = value: ''"${builtins.replaceStrings ["\\" "\"" "$" "\n" "\r"] ["\\\\" "\\\"" "\\$" "\\n" ""] value}"'';
    renderServers = contribution:
      builtins.concatStringsSep "\n" (
        builtins.map
        (virtualHost: ''
          server {
            listen ${contribution.value.consumer_probe.address}:${builtins.toString contribution.value.consumer_probe.port};
            ${
            if virtualHost.tls or false
            then "listen 18443 ssl;"
            else ""
          }
            server_name ${virtualHost.host};
            location = / {
              return 200 ${quote "${virtualHost.response_identity}:${virtualHost.response_content}\n"};
            }
          }
        '')
        contribution.value.virtualHosts
      );
    renderConsumerObservation = contribution: ''
      server {
        listen ${contribution.value.consumer_probe.address}:${builtins.toString contribution.value.consumer_probe.port};
        server_name aos-consumer.invalid;
        location = /__aos/consumer {
          add_header X-AOS-Consumer-Instance ${quote contribution.value.consumer_instance} always;
          add_header X-AOS-Consumer-Controller-Revision ${quote contribution.value.consumer_controller_revision} always;
          add_header X-AOS-Consumer-Content-Revision ${quote contribution.value.consumer_content_revision} always;
          return 204;
        }
      }
    '';
    render = contribution: ''
      worker_processes 1;
      error_log stderr;
      pid nginx.pid;

      events {
        worker_connections 128;
      }

      http {
        access_log off;
        client_body_temp_path client_body;
        proxy_temp_path proxy;
        fastcgi_temp_path fastcgi;
        uwsgi_temp_path uwsgi;
        scgi_temp_path scgi;

      ${renderConsumerObservation contribution}
      ${renderServers contribution}
      }
    '';
    fieldMap = makeValue:
      builtins.listToAttrs (
        builtins.map
        (contribution: {
          name = contribution.slot;
          value = makeValue contribution;
        })
        contributions
      );
    effectsRequest = {
      id = {
        consumer = context.provider;
        scope = [context.provider.key];
        key = "effects";
      };
      accepted_interfaces = [effectsInterface];
      methods = ["prepare" "publish" "release"];
      guarantees = [];
      lifetime = "instance";
    };
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
          group = "configuration";
        };
        interface = managedConfiguration;
        port = "published-configurations";
        value = {
          source = "object";
          fields = fieldMap (contribution: {
            source = "resource-reference";
            reference = {
              interface = managedConfiguration;
              resource = resourceFor contribution;
              operations = ["prepare" "publish" "read" "release"];
              lifetime = "instance";
            };
          });
        };
      }
      {
        aggregate = {
          provider = context.provider;
          group = "configuration";
        };
        interface = managedConfiguration;
        port = "rendered-configurations";
        value = {
          source = "object";
          fields = fieldMap (contribution: {
            source = "literal";
            value = render contribution;
          });
        };
      }
    ];
    controllers =
      builtins.map
      (contribution: {
        resource = resourceFor contribution;
        controller = {
          provider = context.provider;
          group = "configuration";
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
        builtins.elem change.kind [
          "create"
          "update"
          "reconcile-divergent"
        ])
      context.changes;
    removed = builtins.filter (change: change.kind == "remove") context.changes;
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
      else throw "managed-configuration transition requires exactly one authorized ${authorityRole} effects binding for ${method} on ${change.resource.key}";
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
      else throw "managed-configuration transition requires one resource controller";
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
        # The native adapter resolves cancellation through the same exact
        # postcondition check as reconciliation for this filesystem action.
        cancel = {
          interface = terminal.interface;
          inherit method;
        };
        compensate = null;
      };
    };
    prepares =
      builtins.map
      (change: operation "desired" change "prepare" {kind = "prepare-managed-configuration";} "preparing")
      changed;
    publishes =
      builtins.map
      (change: operation "desired" change "publish" {kind = "publish-configuration";} "publishing")
      changed;
    releases =
      builtins.map
      (change: operation "teardown" change "release" {kind = "release-resource";} "converging")
      removed;
    edges =
      builtins.map
      (change: {
        from = node "prepare-${change.resource.key}";
        to = node "publish-${change.resource.key}";
        kind = "required-success";
      })
      changed;
    exports =
      builtins.concatMap
      (change: [
        {
          key = "prepared-${change.resource.key}";
          kind = "completion";
          node = node "prepare-${change.resource.key}";
          outputs = {};
        }
        {
          key = "publish-entry-${change.resource.key}";
          kind = "entry";
          node = node "publish-${change.resource.key}";
          outputs = {};
        }
        {
          key = "published-${change.resource.key}";
          kind = "completion";
          node = node "publish-${change.resource.key}";
          outputs = {};
        }
      ])
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
    dependencyRank = kind:
      builtins.getAttr kind {
        data = 0;
        required-success = 1;
        ordering-only = 2;
        readiness = 3;
        branch-guard = 4;
        branch-merge = 5;
        retention = 6;
        communication = 7;
      };
    operationLess = left: right: left.key.key < right.key.key;
    edgeLess = left: right:
      if left.from.key.key != right.from.key.key
      then left.from.key.key < right.from.key.key
      else if left.to.key.key != right.to.key.key
      then left.to.key.key < right.to.key.key
      else dependencyRank left.kind < dependencyRank right.kind;
    exportLess = left: right: left.key < right.key;
    fragment = {
      schema = "aos.ability.transition-fragment/v1";
      # Every authored node uses context.operation_scope and the operation
      # variant, so the remaining fields in the schema comparators are these
      # local keys and the dependency-kind rank.
      operations = builtins.sort operationLess (prepares ++ publishes ++ releases);
      decisions = [];
      merges = [];
      edges = builtins.sort edgeLess edges;
      exports = builtins.sort exportLess (exports ++ releaseExports);
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
        edges = [];
        exports = [];
      }
    else fragment;
}
