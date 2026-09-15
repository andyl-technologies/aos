##! Pure lifecycle provider for package-owned logical services.
{spec}: let
  inherit (spec.serviceManagement) interface features;
  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };

  isRevision = value:
    builtins.isString value
    && builtins.match "sha256:[0-9a-f]{64}" value != null;

  requireConfiguration = context: let
    configuration = context.configuration;
    unknown =
      builtins.filter
      (name: !(builtins.elem name ["enabled" "restart_token"]))
      (builtins.attrNames configuration);
    restartToken = configuration.restart_token or null;
    automaticRevision =
      context.activation_revision
      or (throw "service ability requires a centrally derived activation revision");
    revision =
      if restartToken != null
      then "sha256:${builtins.hashString "sha256" (builtins.toJSON {
        schema = "aos.service-restart-token/v1";
        automatic_revision = automaticRevision;
        restart_token = restartToken;
      })}"
      else automaticRevision;
  in
    if unknown != []
    then throw "service ability configuration contains unknown fields: ${builtins.concatStringsSep ", " unknown}"
    else if !builtins.isBool configuration.enabled
    then throw "service ability configuration enabled field must be Boolean"
    else if restartToken != null && !builtins.isString restartToken
    then throw "service ability restart token must be a string"
    else if !isRevision automaticRevision
    then throw "service ability activation revision must be a canonical SHA-256 digest"
    else configuration // {inherit revision;};

  resourceFor = provider: service: {
    inherit provider;
    key = service.key;
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
    configuration = requireConfiguration context;
    resources =
      builtins.map (service: {
        resource = resourceFor context.provider service;
        inherit service;
      })
      spec.services;
  in
    if context.interface.name != spec.interface
    then throw "service ability provider received interface '${context.interface.name}', expected '${spec.interface}'"
    else {
      schema = "aos.ability.composition-fragment/v1";
      requests = [
        {
          id = {
            consumer = context.provider;
            scope = [context.provider.key];
            key = "service-terminal";
          };
          accepted_interfaces = [interface];
          inherit (spec) methods;
          guarantees = builtins.map (name: features.${name}) spec.features;
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
    selectedBindings =
      builtins.filter (
        entry:
          entry.binding.request.consumer
          == context.provider
          && entry.binding.interface == interface
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
      else throw "service ability transition requires one ${role} manager binding for ${method}";
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
          method = "restart";
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
          interface = binding.interface;
          method = "observe";
        };
        cancel = {
          interface = binding.interface;
          method = "observe";
        };
        compensate = null;
      };
    };
    operations =
      builtins.concatMap (
        change: builtins.map (operationFor change) (routesFor change)
      )
      context.changes;
    operationForService = service: let
      resource = resourceFor context.provider service;
      matches = builtins.filter (change: change.resource == resource) context.changes;
      change =
        if builtins.length matches == 1
        then builtins.head matches
        else null;
      routes =
        if change == null
        then []
        else routesFor change;
    in
      if builtins.length routes == 1
      then {
        inherit resource;
        method = (builtins.head routes).method;
      }
      else null;
    dependencyEdgesFor = service: let
      serviceOperation = operationForService service;
    in
      builtins.concatMap (dependency: let
        matches = builtins.filter (candidate: candidate.key == dependency) spec.services;
        dependencyService =
          if builtins.length matches == 1
          then builtins.head matches
          else throw "logical service '${service.key}' has unknown dependency '${dependency}'";
        dependencyOperation = operationForService dependencyService;
        bothStopping =
          serviceOperation
          != null
          && dependencyOperation != null
          && serviceOperation.method == "stop"
          && dependencyOperation.method == "stop";
        bothConverging =
          serviceOperation
          != null
          && dependencyOperation != null
          && serviceOperation.method != "stop"
          && dependencyOperation.method != "stop";
        from =
          if bothStopping
          then serviceOperation
          else dependencyOperation;
        to =
          if bothStopping
          then dependencyOperation
          else serviceOperation;
      in
        if bothStopping || bothConverging
        then [
          {
            from = {
              kind = "operation";
              key = scopedKey "${from.method}-${from.resource.key}";
            };
            to = {
              kind = "operation";
              key = scopedKey "${to.method}-${to.resource.key}";
            };
            kind = "required-success";
          }
        ]
        else [])
      service.dependencies;
    edges = builtins.concatMap dependencyEdgesFor spec.services;
  in
    if context.interface.name != spec.interface
    then throw "service ability provider received interface '${context.interface.name}', expected '${spec.interface}'"
    else emptyTransition // {inherit operations edges;};
}
