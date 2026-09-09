##! Pure managed-configuration provider for the checked source fixture.
let
  effectsInterface = {
    name = "aos.managed-configuration-effects";
    abi = 1;
    descriptor = "sha256:2b5e3051194f29f19bdf178c7e51f3bc4dbee7b67eafb04cba7953580dd990bf";
  };

  compose = context: let
    managedConfiguration = context.interface;
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    resourceFor = contribution: {
      provider = context.provider;
      key = "${contribution.slot}-configuration";
    };
    render = contribution:
      builtins.concatStringsSep "\n" (
        builtins.map
        (virtualHost: ''
          server {
            listen 80;
            ${
            if virtualHost.tls or false
            then "listen 443 ssl;"
            else ""
          }
            server_name ${virtualHost.host};
          }
        '')
        contribution.value.virtualHosts
      );
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
              operations = ["publish" "read"];
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
      (change: change.kind == "create" || change.kind == "update")
      context.changes;
    removed = builtins.filter (change: change.kind == "remove") context.changes;
    selected =
      builtins.filter
      (entry:
        entry.binding.request.consumer
        == context.provider
        && (
          entry.binding.request.key
          == "effects"
          || (
            entry.authority.role
            == "teardown"
            && entry.authority.source_request.consumer == context.provider
            && entry.authority.source_request.key == "effects"
          )
        )
        && entry.binding.interface == effectsInterface
        && builtins.all
        (method: builtins.elem method entry.binding.caller_grant.methods)
        ["prepare" "publish" "release"])
      context.authorized_bindings;
    terminal =
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "managed-configuration transition requires exactly one authorized effects binding";
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
    operation = change: method: family: phase: {
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
      deadline = {
        attempt_timeout_millis = 30000;
        total_recovery_millis = 30000;
      };
      recovery = {
        retry = {kind = "disabled";};
        reconcile = null;
        cancel = null;
        compensate = null;
      };
    };
    prepares =
      builtins.map
      (change: operation change "prepare" {kind = "prepare-managed-configuration";} "preparing")
      changed;
    publishes =
      builtins.map
      (change: operation change "publish" {kind = "publish-configuration";} "publishing")
      changed;
    releases =
      builtins.map
      (change: operation change "release" {kind = "release-resource";} "converging")
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
    fragment = {
      schema = "aos.ability.transition-fragment/v1";
      operations = prepares ++ publishes ++ releases;
      decisions = [];
      merges = [];
      inherit edges;
      exports = exports ++ releaseExports;
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
