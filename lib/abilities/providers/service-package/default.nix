##! Pure lifecycle provider for package-owned systemd targets.
let
  catalog = import ./catalog.nix;
  systemdEffects = {
    name = "aos.systemd-service-effects";
    abi = 1;
    descriptor = "sha256:383803bfd7eb105968a80a796fc4726b5663890e88220d26b20dbd2b33349b50";
  };
  localSystemdManager = {
    name = "aos.local-systemd-manager";
    version = 1;
    descriptor = "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4";
  };
  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };

  specFor = interface: let
    matches = builtins.filter (
      packageName: catalog.${packageName}.interface == interface.name
    ) (builtins.attrNames catalog);
  in
    if builtins.length matches == 1
    then catalog.${builtins.head matches}
    else throw "service ability provider does not recognize interface '${interface.name}'";

  requireConfiguration = configuration:
    if !builtins.isBool configuration.enabled
    then throw "service ability configuration enabled field must be Boolean"
    else if builtins.match "sha256:[0-9a-f]{64}" configuration.revision == null
    then throw "service ability configuration revision must be a canonical SHA-256 digest"
    else configuration;

  resourceFor = provider: unit: {
    inherit provider;
    key = builtins.replaceStrings ["." "_"] ["-" "-"] unit;
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
in {
  compose = context: let
    spec = specFor context.interface;
    configuration = requireConfiguration context.configuration;
    resources =
      builtins.map (unit: {
        resource = resourceFor context.provider unit;
        inherit unit;
      })
      spec.units;
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests = [
      {
        id = {
          consumer = context.provider;
          scope = [context.provider.key];
          key = "service-terminal";
        };
        accepted_interfaces = [systemdEffects];
        methods = ["start" "stop"];
        guarantees = [localSystemdManager];
        lifetime = "instance";
      }
    ];
    contributions = [];
    resources =
      if configuration.enabled
      then
        builtins.map (entry: {
          inherit (entry) resource;
          inherit (configuration) revision;
        })
        resources
      else [];
    outputs = [];
    controllers =
      if configuration.enabled
      then
        builtins.map (entry: {
          inherit (entry) resource;
          controller = {
            provider = context.provider;
            group = "service";
          };
        })
        resources
      else [];
  };

  transition = context: let
    spec = specFor context.interface;
    selectedBindings =
      builtins.filter (
        entry:
          entry.binding.request.consumer
          == context.provider
          && entry.binding.interface == systemdEffects
          && (
            entry.binding.request.key
            == "service-terminal"
            || (
              entry.authority.role
              == "teardown"
              && entry.authority.source_request.consumer == context.provider
              && entry.authority.source_request.key == "service-terminal"
            )
          )
      )
      context.authorized_bindings;
    bindingFor = role: method: let
      matches =
        builtins.filter (
          entry:
            entry.authority.role
            == role
            && builtins.elem method entry.binding.caller_grant.methods
        )
        selectedBindings;
    in
      if builtins.length matches == 1
      then (builtins.head matches).binding
      else throw "service ability transition requires one ${role} systemd binding for ${method}";
    scopedKey = key: {
      scope = context.operation_scope;
      inherit key;
    };
    controllerFor = resource: let
      matches = builtins.filter (entry: entry.resource == resource) context.controllers;
    in
      if builtins.length matches == 1
      then (builtins.head matches).controller
      else null;
    unitFor = resource: let
      matches =
        builtins.filter (
          unit: resource == resourceFor context.provider unit
        )
        spec.units;
    in
      if builtins.length matches == 1
      then builtins.head matches
      else throw "service ability transition contains an unknown package unit resource";
    routesFor = change:
      if change.kind == "create" || change.kind == "reconcile-stopped"
      then [
        {
          role = "desired";
          method = "start";
        }
      ]
      else if change.kind == "update" || change.kind == "reconcile-divergent"
      then [
        {
          role = "desired";
          method = "stop";
        }
        {
          role = "desired";
          method = "start";
        }
      ]
      else if change.kind == "remove"
      then [
        {
          role = "teardown";
          method = "stop";
        }
      ]
      else [];
    operationFor = change: route: let
      binding = bindingFor route.role route.method;
    in {
      key = scopedKey "${route.method}-${change.resource.key}";
      branch_context = [];
      binding = binding.id;
      authority = "caller";
      interface = binding.interface;
      method = route.method;
      family = {
        kind = "service-lifecycle";
        action = route.method;
      };
      phase = "converging";
      input_phase = "planning";
      target = {
        interface = binding.interface;
        resource = change.resource;
        operations = [route.method];
        lifetime = "instance";
      };
      inputs = {
        source = "literal";
        value = {unit = unitFor change.resource;};
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
          interface = binding.interface;
          method = route.method;
        };
        cancel = {
          interface = binding.interface;
          method = route.method;
        };
        compensate = null;
      };
    };
    operations =
      builtins.concatMap (
        change: builtins.map (operationFor change) (routesFor change)
      )
      context.changes;
    restartChanges =
      builtins.filter (
        change: change.kind == "update" || change.kind == "reconcile-divergent"
      )
      context.changes;
    edges =
      builtins.map (change: {
        from = {
          kind = "operation";
          key = scopedKey "stop-${change.resource.key}";
        };
        to = {
          kind = "operation";
          key = scopedKey "start-${change.resource.key}";
        };
        kind = "required-success";
      })
      restartChanges;
  in
    emptyTransition // {inherit operations edges;};
}
