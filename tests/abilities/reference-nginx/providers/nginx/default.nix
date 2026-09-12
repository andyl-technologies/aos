##! Pure nginx aggregate provider for the checked source-composition fixture.
let
  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  managedConfiguration =
    interface
    "aos.managed-configuration"
    "sha256:771c63c0fe1730c0592b49c14600a115b2c842d5b363d66158b918ccd051ee3d";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:d282faba1d3a1afd3ed7b2cde885331d8c2cf94f9b7968eb88987cffae852a3b";
  systemdService =
    interface
    "aos.systemd-service"
    "sha256:b712c9e3697e87d62bb62549d8692b4d8f825bae9733ae523f76a40bd3882666";
  nginxValidation =
    interface
    "aos.nginx-validation"
    "sha256:c781b7f06eabaa9386ab0438f150b028e98b6d07ad78a907a567d27ee14602a6";
  systemdEffects =
    interface
    "aos.systemd-service-effects"
    "sha256:383803bfd7eb105968a80a796fc4726b5663890e88220d26b20dbd2b33349b50";
  foregroundProcess =
    interface
    "aos.foreground-process"
    "sha256:6f692b67b0670968fb335b4ebe93951cd40bdedf925f98f025b93024b30b17cb";

  localSystemdManagerGuarantee = {
    name = "aos.local-systemd-manager";
    version = 1;
    descriptor = "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4";
  };
  systemContainerManagerDelegationGuarantee = {
    name = "aos.system-container-manager-delegation";
    version = 1;
    descriptor = "sha256:a811c4d2cc0fd8e09a019ae518bbe95f393ed5bc3265a1b72902adfa7325ceda";
  };
  foregroundProcessSupervisionGuarantee = {
    name = "aos.foreground-process-supervision";
    version = 1;
    descriptor = "sha256:b213e3c6ef28e4930a1091296e28fbfddde9f539d2daeb0287edfe955047311a";
  };

  # Recovery conservatively charges a full interrupted call. Four call-sized
  # slices retain room for that attempt, reconciliation, a retry, and a final
  # reconciliation; one slice also spans a reference VM boot.
  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };

  childRequest = context: scope: key: acceptedInterface: guarantees: {
    id = {
      consumer = context.provider;
      inherit scope key;
    };
    accepted_interfaces = [acceptedInterface];
    methods = [];
    inherit guarantees;
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

  projectMapEntry = context: binding: sourceInterface: group: sourcePort: outputInterface: port:
    if binding == null
    then []
    else let
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

  validResponseIdentity = identity:
    builtins.isString identity
    && builtins.stringLength identity <= 128
    && builtins.match "[A-Za-z0-9._-]+" identity != null;

  validResponseContent = content:
    builtins.isString content
    && builtins.stringLength content > 0
    && builtins.stringLength content <= 256
    && builtins.match "[-A-Za-z0-9._:/ ]+" content != null;

  validateConsumerProbe = probe:
    if probe.address != "127.0.0.1"
    then throw "nginx consumer probe must use the IPv4 loopback address"
    else if probe.port < 1024 || probe.port > 65535
    then throw "nginx consumer probe port is outside the unprivileged TCP range"
    else probe;

  validateExecutionStrategy = stage: strategy:
    if
      strategy
      == "systemd-manager"
      && builtins.elem stage ["host" "system-container"]
    then strategy
    else if strategy == "foreground-process" && stage == "application-container"
    then strategy
    else throw "nginx execution strategy is incompatible with its execution stage";

  validateVirtualHost = contribution: let
    virtualHost = contribution.value;
  in
    if !validServerName virtualHost.host
    then throw "nginx contribution host is not a valid DNS server name"
    else if !validResponseIdentity virtualHost.response_identity
    then throw "nginx contribution response identity is invalid"
    else if virtualHost.response_identity != contribution.slot
    then throw "nginx contribution response identity does not match its authorized slot"
    else if !validResponseContent virtualHost.response_content
    then throw "nginx contribution response content is invalid"
    else virtualHost;

  compose = context: let
    nginx = context.interface;
    scope = [context.provider.key];
    validated =
      builtins.foldl'
      (state: contribution: let
        virtualHost = validateVirtualHost contribution;
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
    consumerProbe = validateConsumerProbe context.configuration;
    tlsHosts =
      builtins.filter
      (virtualHost: virtualHost.tls or false)
      virtualHosts;

    executionStage = context.provider.environment.stage;
    executionStrategy = validateExecutionStrategy executionStage consumerProbe.execution_strategy;
    usesSystemd = executionStrategy == "systemd-manager";
    configurationRequest = childRequest context scope "configuration" managedConfiguration [];
    credentialRequest = childRequest context scope "credential" credentialDelivery [];
    serviceRequest =
      if usesSystemd
      then childRequest context scope "service" systemdService []
      else null;
    validationRequest = childRequest context scope "validation-terminal" nginxValidation [];
    serviceTerminalRequest =
      if executionStage == "host"
      then childRequest context scope "service-terminal" systemdEffects [localSystemdManagerGuarantee]
      else if executionStage == "system-container"
      then
        childRequest context scope "service-terminal-system-container" systemdEffects [
          localSystemdManagerGuarantee
          systemContainerManagerDelegationGuarantee
        ]
      else
        childRequest context scope "service-terminal-foreground" foregroundProcess [
          foregroundProcessSupervisionGuarantee
        ];
    usesTls = tlsHosts != [];
    requests =
      [configurationRequest]
      ++ (
        if usesTls
        then [credentialRequest]
        else []
      )
      ++ (
        if serviceRequest == null
        then []
        else [serviceRequest]
      )
      ++ [serviceTerminalRequest validationRequest];
    validationRequestWithMethod = validationRequest // {methods = ["record" "release" "validate"];};
    serviceTerminalRequestWithMethods =
      serviceTerminalRequest
      // {
        methods =
          if usesSystemd
          then ["observe" "reload" "start" "stop"]
          else ["observe" "start" "stop"];
      };

    configurationBinding = bindingFor context configurationRequest;
    credentialBinding = bindingFor context credentialRequest;
    serviceBinding =
      if serviceRequest == null
      then null
      else bindingFor context serviceRequest;
    configurationRevision = "sha256:${builtins.hashString "sha256" (builtins.toJSON virtualHosts)}";
    serviceValue = {
      configuration_revision = configurationRevision;
      consumer_endpoint = "${consumerProbe.address}:${builtins.toString consumerProbe.port}";
      unit = "nginx-${context.provider.key}.service";
      virtual_host_count = builtins.length virtualHosts;
    };
    serviceRevision = "sha256:${builtins.hashString "sha256" (builtins.toJSON serviceValue)}";
    contributions =
      lowerContribution context configurationRequest "configuration" {
        inherit virtualHosts;
        consumer_content_revision = configurationRevision;
        consumer_controller_revision = serviceRevision;
        consumer_instance = builtins.toJSON context.provider;
        consumer_probe = consumerProbe;
      }
      ++ (
        if usesTls
        then
          lowerContribution context credentialRequest "credentials" {
            hosts = builtins.map (virtualHost: virtualHost.host) tlsHosts;
          }
        else []
      )
      ++ (
        if serviceRequest == null
        then []
        else lowerContribution context serviceRequest "services" serviceValue
      );
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests =
      builtins.map
      (request:
        if request.id.key == "validation-terminal"
        then validationRequestWithMethod
        else if
          builtins.elem request.id.key [
            "service-terminal"
            "service-terminal-foreground"
            "service-terminal-system-container"
          ]
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
    bindingsFor = requestKey: expectedInterface: requiredMethods:
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
    desiredBinding = requestKey: expectedInterface: requiredMethods: let
      selected = bindingsFor requestKey expectedInterface requiredMethods;
    in
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "nginx transition requires exactly one authorized ${requestKey} binding";
    optionalBinding = requestKey: expectedInterface: requiredMethods: let
      selected = bindingsFor requestKey expectedInterface requiredMethods;
    in
      if selected == []
      then null
      else if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "nginx transition permits at most one authorized ${requestKey} binding";
    validation = desiredBinding "validation-terminal" nginxValidation ["record" "release" "validate"];
    configuration = desiredBinding "configuration" managedConfiguration [];
    credential = optionalBinding "credential" credentialDelivery [];
    executionStage = context.provider.environment.stage;
    usesForeground = executionStage == "application-container";
    service =
      if usesForeground
      then null
      else desiredBinding "service" systemdService [];
    serviceTerminal =
      if executionStage == "host"
      then desiredBinding "service-terminal" systemdEffects ["observe" "reload" "start" "stop"]
      else if executionStage == "system-container"
      then desiredBinding "service-terminal-system-container" systemdEffects ["observe" "reload" "start" "stop"]
      else desiredBinding "service-terminal-foreground" foregroundProcess ["observe" "start" "stop"];
    resourcesGrantedBy = binding:
      builtins.map (permission: permission.resource) binding.caller_grant.resources;
    changesThrough = binding:
      builtins.filter
      (change:
        builtins.elem change.resource (resourcesGrantedBy binding))
      context.changes;
    optionalChangesThrough = binding:
      if binding == null
      then []
      else changesThrough binding;
    createdOrUpdated =
      builtins.filter
      (change:
        builtins.elem change.kind [
          "create"
          "update"
          "reconcile-stopped"
          "reconcile-divergent"
        ]);
    configurationChanged = createdOrUpdated (changesThrough configuration);
    credentialChanges = optionalChangesThrough credential;
    credentialChanged = createdOrUpdated credentialChanges;
    credentialRemoved = builtins.filter (change: change.kind == "remove") credentialChanges;
    serviceChanged = createdOrUpdated (changesThrough service);
    owned =
      builtins.filter
      (change: change.resource.provider == context.provider)
      context.changes;
    retained = builtins.filter (change: change.kind != "remove") owned;
    removed = builtins.filter (change: change.kind == "remove") owned;
    serviceAction =
      if
        builtins.any
        (change: builtins.elem change.kind ["create" "reconcile-stopped"])
        serviceChanged
      then "start"
      else "reload";
    serviceResources = serviceTerminal.caller_grant.resources;
    serviceResource =
      if builtins.length serviceResources == 1
      then (builtins.head serviceResources).resource
      else throw "nginx transition requires exactly one authorized service resource";
    needsValidation = configurationChanged != [] || credentialChanged != [];
    credentialAvailable =
      if needsValidation
      then
        builtins.filter
        (change:
          change.kind
          == "create"
          || change.kind == "update"
          || change.kind == "unchanged"
          || change.kind == "reconcile-stopped"
          || change.kind == "reconcile-divergent")
        credentialChanges
      else [];
    needsConvergence = needsValidation || serviceChanged != [];
    needsAssociation =
      needsConvergence
      || builtins.any
      (change:
        builtins.elem change.kind [
          "create"
          "update"
          "reconcile-stopped"
          "reconcile-divergent"
        ])
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
    lowerOperationResult = binding: operation: output: {
      source = "operation-result";
      reference = {
        producer = {
          kind = "operation";
          key = {
            scope = [
              binding.provider.key
              (builtins.substring 7 64 binding.implementation.descriptor)
            ];
            key = operation;
          };
        };
        inherit output;
      };
    };
    credentialMethod = change:
      if change.kind == "unchanged"
      then "acquire"
      else "deliver";
    credentialViewInputs =
      builtins.map
      (change:
        lowerOperationResult
        credential
        "${credentialMethod change}-${change.resource.key}"
        "credential-view")
      credentialAvailable;
    validationInputs = candidate: credentialViews: {
      source = "object";
      fields = {
        candidate = {
          source = "literal";
          value = candidate;
        };
        credential_views = {
          source = "list";
          items = credentialViews;
        };
      };
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
      input_phase = "runtime";
      target = {
        interface = validation.interface;
        resource = change.resource;
        operations = ["validate"];
        lifetime = "instance";
      };
      inputs = validationInputs true credentialViewInputs;
      preconditions = [];
      accesses = [
        {
          resource = change.resource;
          mode = "read";
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
          interface = validation.interface;
          method = "validate";
        };
        cancel = {
          interface = validation.interface;
          method = "validate";
        };
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
      inputs = validationInputs true [];
      preconditions = [];
      accesses = [
        {
          resource = change.resource;
          mode = "shared-write";
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
          interface = validation.interface;
          method = "record";
        };
        cancel = {
          interface = validation.interface;
          method = "record";
        };
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
      deadline = operationDeadline;
      recovery = {
        retry = {kind = "disabled";};
        reconcile =
          if action == "stop"
          then {
            interface = serviceTerminal.interface;
            method = "observe";
          }
          else null;
        # Active state cannot prove that start or reload took effect. A stopped
        # state is an exact postcondition for cancelling Stop.
        cancel =
          if action == "stop"
          then {
            interface = serviceTerminal.interface;
            method = "observe";
          }
          else null;
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
      deadline = operationDeadline;
      recovery = {
        retry = {kind = "disabled";};
        reconcile = {
          interface = serviceTerminal.interface;
          method = "observe";
        };
        cancel = {
          interface = serviceTerminal.interface;
          method = "observe";
        };
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
      inputs = validationInputs false [];
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
          interface = validation.interface;
          method = "release";
        };
        cancel = {
          interface = validation.interface;
          method = "release";
        };
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
    credentialImports =
      builtins.concatMap
      (change:
        builtins.map
        (association: {
          binding = credential.id;
          export = "view-${change.resource.key}";
          direction = "after-export";
          outputs = ["credential-view"];
          consumer = node "validate-${association.resource.key}";
          kind = "data";
        })
        associationChanges)
      credentialAvailable;
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
    credentialReleaseImports =
      builtins.map
      (change: {
        binding = credential.id;
        export = "release-entry-${change.resource.key}";
        direction = "before-export";
        outputs = [];
        consumer =
          if removed != []
          then node "stop-${serviceResource.key}"
          else node "observe-${serviceResource.key}";
        kind = "required-success";
      })
      credentialRemoved;
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
    credentialOnlyEdges =
      if credentialChanged != [] && configurationChanged == []
      then
        builtins.map
        (change: {
          from = node "validate-${change.resource.key}";
          to = node "${serviceAction}-${serviceResource.key}";
          kind = "required-success";
        })
        associationChanges
      else [];
    teardownEdges =
      builtins.map
      (change: {
        from = node "stop-${serviceResource.key}";
        to = node "release-${change.resource.key}";
        kind = "required-success";
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
    directionRank = direction:
      builtins.getAttr direction {
        after-export = 0;
        before-export = 1;
      };
    operationLess = left: right: left.key.key < right.key.key;
    edgeLess = left: right:
      if left.from.key.key != right.from.key.key
      then left.from.key.key < right.from.key.key
      else if left.to.key.key != right.to.key.key
      then left.to.key.key < right.to.key.key
      else dependencyRank left.kind < dependencyRank right.kind;
    importLess = left: right:
      if left.binding != right.binding
      then left.binding < right.binding
      else if left.export != right.export
      then left.export < right.export
      else if left.direction != right.direction
      then directionRank left.direction < directionRank right.direction
      else if left.consumer.key.key != right.consumer.key.key
      then left.consumer.key.key < right.consumer.key.key
      else dependencyRank left.kind < dependencyRank right.kind;
    fragment = {
      schema = "aos.ability.transition-fragment/v1";
      operations =
        builtins.sort operationLess
        (
          (builtins.map validate (
            if needsValidation
            then associationChanges
            else []
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
        builtins.sort edgeLess
        (convergenceEdges ++ credentialOnlyEdges ++ teardownEdges);
      exports = [];
      imports = builtins.sort importLess (
        configurationImports
        ++ credentialImports
        ++ convergenceImports
        ++ teardownImports
        ++ credentialReleaseImports
      );
      links = [];
      handoffs = [];
      provider_readiness = [];
      obligations = [];
    };
  in
    if usesForeground
    then throw "nginx foreground activation remains an unresolved deployment obligation"
    else if associationChanges == [] && removed == [] && credentialRemoved == []
    then
      fragment
      // {
        operations = [];
        imports = [];
        links = [];
      }
    else fragment;
}
