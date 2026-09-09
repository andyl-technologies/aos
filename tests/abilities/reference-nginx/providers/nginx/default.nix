##! Pure nginx aggregate provider for the checked source-composition fixture.
let
  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  managedConfiguration =
    interface
    "aos.managed-configuration"
    "sha256:41dd1b3848c02d69542c61cdb871d588979139b321afff0edd3942c9d008fa3a";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:d282faba1d3a1afd3ed7b2cde885331d8c2cf94f9b7968eb88987cffae852a3b";
  systemdService =
    interface
    "aos.systemd-service"
    "sha256:1be97040a30ac274816ff7d1ee53f384989165f2ed09c80956a1d90458b72f5f";
  nginxValidation =
    interface
    "aos.nginx-validation"
    "sha256:cfe3335b1ff3082ffd17e38f098e804461daaa32db19a2aba9faa2e2acaddd1d";
  systemdEffects =
    interface
    "aos.systemd-service-effects"
    "sha256:08e463bed96f053e557f557c95342666e81358396a44f89bf4c07a2aa780d6c5";

  childRequest = context: scope: key: acceptedInterface: {
    id = {
      consumer = context.provider;
      inherit scope key;
    };
    accepted_interfaces = [acceptedInterface];
    methods = [];
    guarantees = [];
    lifetime = "instance";
  };

  bindingFor = context: request: let
    selected =
      builtins.filter
      (binding: binding.request == request.id)
      context.bindings;
  in
    if selected == []
    then null
    else builtins.head selected;

  lowerContribution = context: request: group: value: let
    binding = bindingFor context request;
  in
    if binding == null
    then []
    else [
      {
        request = request.id;
        aggregate = {
          provider = binding.provider;
          inherit group;
        };
        slot = context.provider.key;
        grant = binding.id;
        inherit value;
      }
    ];

  outputFrom = context: binding: sourceInterface: group: port:
    if binding == null
    then []
    else
      builtins.filter
      (output:
        output.aggregate.provider
        == binding.provider
        && output.aggregate.group == group
        && output.interface == sourceInterface
        && output.port == port)
      context.outputs;

  projectMapEntry = context: binding: sourceInterface: group: sourcePort: outputInterface: port: let
    selected = outputFrom context binding sourceInterface group sourcePort;
  in
    if
      selected
      == []
      || !builtins.hasAttr context.provider.key (builtins.head selected).value.fields
    then []
    else [
      {
        aggregate = {
          provider = context.provider;
          group = "nginx";
        };
        interface = outputInterface;
        inherit port;
        value = (builtins.head selected).value.fields.${context.provider.key};
      }
    ];

  validServerName = host:
    builtins.isString host
    && builtins.stringLength host <= 253
    && builtins.match
    "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+"
    host
    != null;

  validateVirtualHost = virtualHost:
    if validServerName virtualHost.host
    then virtualHost
    else throw "nginx contribution host is not a valid DNS server name";

  compose = context: let
    nginx = context.interface;
    scope = [context.provider.key];
    validated =
      builtins.foldl'
      (state: contribution: let
        virtualHost = validateVirtualHost contribution.value;
      in
        if builtins.hasAttr virtualHost.host state.claimedHosts
        then throw "nginx contributions contain a duplicate server name"
        else {
          virtualHosts = state.virtualHosts ++ [virtualHost];
          claimedHosts = state.claimedHosts // {${virtualHost.host} = true;};
        })
      {
        virtualHosts = [];
        claimedHosts = {};
      }
      context.contributions;
    virtualHosts = validated.virtualHosts;
    tlsHosts =
      builtins.filter
      (virtualHost: virtualHost.tls or false)
      virtualHosts;

    configurationRequest = childRequest context scope "configuration" managedConfiguration;
    credentialRequest = childRequest context scope "credential" credentialDelivery;
    serviceRequest = childRequest context scope "service" systemdService;
    validationRequest = childRequest context scope "validation-terminal" nginxValidation;
    serviceTerminalRequest = childRequest context scope "service-terminal" systemdEffects;
    usesTls = tlsHosts != [];
    requests =
      [configurationRequest]
      ++ (
        if usesTls
        then [credentialRequest]
        else []
      )
      ++ [serviceRequest serviceTerminalRequest validationRequest];
    validationRequestWithMethod = validationRequest // {methods = ["record" "release" "validate"];};
    serviceTerminalRequestWithMethods = serviceTerminalRequest // {methods = ["observe" "reload" "start" "stop"];};

    configurationBinding = bindingFor context configurationRequest;
    credentialBinding = bindingFor context credentialRequest;
    serviceBinding = bindingFor context serviceRequest;
    contributions =
      lowerContribution context configurationRequest "configuration" {
        inherit virtualHosts;
      }
      ++ (
        if usesTls
        then
          lowerContribution context credentialRequest "credentials" {
            hosts = builtins.map (virtualHost: virtualHost.host) tlsHosts;
          }
        else []
      )
      ++ lowerContribution context serviceRequest "services" {
        configuration_revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON virtualHosts)}";
        unit = "nginx-${context.provider.key}.service";
        virtual_host_count = builtins.length virtualHosts;
      };
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests =
      builtins.map
      (request:
        if request.id.key == "validation-terminal"
        then validationRequestWithMethod
        else if request.id.key == "service-terminal"
        then serviceTerminalRequestWithMethods
        else request)
      requests;
    inherit contributions;
    resources = [
      {
        resource = {
          provider = context.provider;
          key = "virtual-hosts";
        };
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON virtualHosts)}";
      }
    ];
    outputs =
      projectMapEntry context configurationBinding managedConfiguration "configuration" "published-configurations" nginx "configuration"
      ++ projectMapEntry context credentialBinding credentialDelivery "credentials" "credential-views" nginx "credential-view"
      ++ projectMapEntry context serviceBinding systemdService "services" "managers" nginx "manager"
      ++ projectMapEntry context configurationBinding managedConfiguration "configuration" "rendered-configurations" nginx "rendered-configuration"
      ++ [
        {
          aggregate = {
            provider = context.provider;
            group = "nginx";
          };
          interface = nginx;
          port = "virtual-host-count";
          value = {
            source = "literal";
            value = builtins.length virtualHosts;
          };
        }
      ];
    controllers = [
      {
        resource = {
          provider = context.provider;
          key = "virtual-hosts";
        };
        controller = {
          provider = context.provider;
          group = "nginx";
        };
      }
    ];
  };
in {
  inherit compose;

  transition = context: let
    desiredBinding = requestKey: expectedInterface: requiredMethods: let
      selected =
        builtins.filter
        (entry:
          entry.binding.request.consumer
          == context.provider
          && (
            entry.binding.request.key
            == requestKey
            || (
              entry.authority.role
              == "teardown"
              && entry.authority.source_request.consumer == context.provider
              && entry.authority.source_request.key == requestKey
            )
          )
          && entry.binding.interface == expectedInterface
          && builtins.all
          (method: builtins.elem method entry.binding.caller_grant.methods)
          requiredMethods)
        context.authorized_bindings;
    in
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "nginx transition requires exactly one authorized ${requestKey} binding";
    validation = desiredBinding "validation-terminal" nginxValidation ["record" "release" "validate"];
    configuration = desiredBinding "configuration" managedConfiguration [];
    service = desiredBinding "service" systemdService [];
    serviceTerminal = desiredBinding "service-terminal" systemdEffects ["observe" "reload" "start" "stop"];
    resourcesGrantedBy = binding:
      builtins.map (permission: permission.resource) binding.caller_grant.resources;
    changedThrough = binding:
      builtins.filter
      (change:
        builtins.elem change.resource (resourcesGrantedBy binding)
        && (change.kind == "create" || change.kind == "update"))
      context.changes;
    configurationChanged = changedThrough configuration;
    serviceChanged = changedThrough service;
    owned =
      builtins.filter
      (change: change.resource.provider == context.provider)
      context.changes;
    retained = builtins.filter (change: change.kind != "remove") owned;
    removed = builtins.filter (change: change.kind == "remove") owned;
    serviceAction =
      if builtins.any (change: change.kind == "create") serviceChanged
      then "start"
      else "reload";
    serviceResources = serviceTerminal.caller_grant.resources;
    serviceResource =
      if builtins.length serviceResources == 1
      then (builtins.head serviceResources).resource
      else throw "nginx transition requires exactly one authorized service resource";
    needsConvergence = configurationChanged != [] || serviceChanged != [];
    needsAssociation =
      needsConvergence
      || builtins.any
      (change: change.kind == "create" || change.kind == "update")
      owned;
    associationChanges =
      if needsAssociation && builtins.length retained == 1
      then [(builtins.head retained)]
      else [];
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
      else throw "nginx transition requires one resource controller";
    validate = change: {
      key = scopedKey "validate-${change.resource.key}";
      branch_context = [];
      binding = validation.id;
      authority = "caller";
      interface = validation.interface;
      method = "validate";
      family = {kind = "validate-candidate";};
      phase = "preparing";
      input_phase = "planning";
      target = {
        interface = validation.interface;
        resource = change.resource;
        operations = ["validate"];
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
          mode = "read";
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
    record = change: {
      key = scopedKey "record-${change.resource.key}";
      branch_context = [];
      binding = validation.id;
      authority = "caller";
      interface = validation.interface;
      method = "record";
      family = {kind = "record-generation-association";};
      phase = "converging";
      input_phase = "planning";
      target = {
        interface = validation.interface;
        resource = change.resource;
        operations = ["record"];
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
          mode = "shared-write";
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
    serviceLifecycle = action: {
      key = scopedKey "${action}-${serviceResource.key}";
      branch_context = [];
      binding = serviceTerminal.id;
      authority = "caller";
      interface = serviceTerminal.interface;
      method = action;
      family = {
        kind = "service-lifecycle";
        inherit action;
      };
      phase = "converging";
      input_phase = "planning";
      target = {
        interface = serviceTerminal.interface;
        resource = serviceResource;
        operations = [action];
        lifetime = "instance";
      };
      inputs = {
        source = "literal";
        value = true;
      };
      preconditions = [];
      accesses = [
        {
          resource = serviceResource;
          mode = "exclusive-write";
        }
      ];
      controller = controllerFor serviceResource;
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
    observeService = {
      key = scopedKey "observe-${serviceResource.key}";
      branch_context = [];
      binding = serviceTerminal.id;
      authority = "caller";
      interface = serviceTerminal.interface;
      method = "observe";
      family = {kind = "observe-readiness";};
      phase = "converging";
      input_phase = "planning";
      target = {
        interface = serviceTerminal.interface;
        resource = serviceResource;
        operations = ["observe"];
        lifetime = "instance";
      };
      inputs = {
        source = "literal";
        value = true;
      };
      preconditions = [];
      accesses = [
        {
          resource = serviceResource;
          mode = "read";
        }
      ];
      controller = controllerFor serviceResource;
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
    release = change: {
      key = scopedKey "release-${change.resource.key}";
      branch_context = [];
      binding = validation.id;
      authority = "caller";
      interface = validation.interface;
      method = "release";
      family = {kind = "release-resource";};
      phase = "converging";
      input_phase = "planning";
      target = {
        interface = validation.interface;
        resource = change.resource;
        operations = ["release"];
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
    configurationImports =
      builtins.concatMap
      (change: [
        {
          binding = configuration.id;
          export = "prepared-${context.provider.key}-configuration";
          direction = "after-export";
          outputs = [];
          consumer = node "validate-${change.resource.key}";
          kind = "required-success";
        }
        {
          binding = configuration.id;
          export = "publish-entry-${context.provider.key}-configuration";
          direction = "before-export";
          outputs = [];
          consumer = node "validate-${change.resource.key}";
          kind = "required-success";
        }
      ])
      (
        if configurationChanged == []
        then []
        else associationChanges
      );
    teardownImports =
      builtins.map
      (change: {
        binding = configuration.id;
        export = "release-entry-${context.provider.key}-configuration";
        direction = "before-export";
        outputs = [];
        consumer = node "stop-${serviceResource.key}";
        kind = "required-success";
      })
      removed;
    convergenceImports =
      builtins.map
      (change: {
        binding = configuration.id;
        export = "published-${context.provider.key}-configuration";
        direction = "after-export";
        outputs = [];
        consumer = node "${serviceAction}-${serviceResource.key}";
        kind = "required-success";
      })
      (
        if configurationChanged == []
        then []
        else associationChanges
      );
    convergenceEdges =
      if needsConvergence
      then [
        {
          from = node "${serviceAction}-${serviceResource.key}";
          to = node "observe-${serviceResource.key}";
          kind = "required-success";
        }
        {
          from = node "observe-${serviceResource.key}";
          to = node "record-${(builtins.head associationChanges).resource.key}";
          kind = "required-success";
        }
      ]
      else [];
    teardownEdges =
      builtins.map
      (change: {
        from = node "stop-${serviceResource.key}";
        to = node "release-${change.resource.key}";
        kind = "required-success";
      })
      removed;
    fragment = {
      schema = "aos.ability.transition-fragment/v1";
      operations =
        builtins.sort
        (left: right: left.key.key < right.key.key)
        (
          (builtins.map validate (
            if configurationChanged == []
            then []
            else associationChanges
          ))
          ++ (builtins.map record associationChanges)
          ++ (builtins.map release removed)
          ++ (
            if needsConvergence
            then [(serviceLifecycle serviceAction) observeService]
            else []
          )
          ++ (
            if removed == []
            then []
            else [(serviceLifecycle "stop")]
          )
        );
      decisions = [];
      merges = [];
      edges =
        builtins.sort
        (left: right: left.from.key.key < right.from.key.key)
        (convergenceEdges ++ teardownEdges);
      exports = [];
      imports = configurationImports ++ convergenceImports ++ teardownImports;
      links = [];
      handoffs = [];
      provider_readiness = [];
      obligations = [];
    };
  in
    if associationChanges == [] && removed == []
    then
      fragment
      // {
        operations = [];
        imports = [];
        links = [];
      }
    else fragment;
}
