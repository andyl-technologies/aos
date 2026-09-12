##! Pure aggregate provider for the authenticated production nginx contract.
let
  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  managedConfiguration =
    interface
    "aos.managed-configuration"
    "sha256:f2f4174c1b63997d056df99fe7eeb1d07c37a52f88588e03163bc8bf536ea802";
  credentialDelivery =
    interface
    "aos.credential-delivery"
    "sha256:e8c5924bd71f8c018958430a91907c662e09af55221d2c94a758dc4a1377d44f";
  systemdService =
    interface
    "aos.systemd-service"
    "sha256:b712c9e3697e87d62bb62549d8692b4d8f825bae9733ae523f76a40bd3882666";
  nginxValidation =
    interface
    "aos.nginx-validation"
    "sha256:6b9bf98724f7bd138b5e0c59806f07b47e9697b61f1f07d9ac4110a294091de6";
  httpBackend =
    interface
    "aos.http-backend"
    "sha256:d2a053b3b69a6c0beddf569db7b1b245262c1bd4dd429b1edf8c5a7361e20dcf";
  endpointEffects =
    interface
    "aos.network-endpoint-effects"
    "sha256:6b4d345ab4350917a04b770f0ac4b82888ffe6ef7e647caa9fe94ccb9f9dac6a";
  networkPolicyEffects =
    interface
    "aos.host-network-policy-effects"
    "sha256:e912beeec7f8d007704910c27cc8c7d3e75267e49679f6ff933577752556df0e";
  storageEffects =
    interface
    "aos.host-storage-effects"
    "sha256:5e0c90d7b65c40e72245dd1350bdae2c9f5c176ceb6caa9cb8789dc5448755c8";
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

  loopbackIngressGuarantee = {
    name = "aos.guarantee.loopback-tcp-ingress-enforcement";
    version = 1;
    descriptor = "sha256:6b12b1c4db768f272434c6e43ca8c484887fc0fa3a51be2ae2784982325c2092";
  };
  loopbackEgressGuarantee = {
    name = "aos.guarantee.loopback-tcp-egress-enforcement";
    version = 1;
    descriptor = "sha256:91fc94f9ff09a955256a2a86d1df6df00e1635c8fc035e2f68e262cbc29dcd53";
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

  validateBackendEndpoint = endpoint:
    if endpoint.address != "127.0.0.1"
    then throw "HTTP backend must use the IPv4 loopback address"
    else if endpoint.port < 1024 || endpoint.port > 65535
    then throw "HTTP backend port is outside the unprivileged TCP range"
    else if endpoint.transport != "tcp"
    then throw "HTTP backend must use TCP"
    else endpoint;

  backendCompose = context: let
    endpoint = validateBackendEndpoint context.configuration;
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests = [];
    contributions = [];
    resources = [];
    outputs = [
      {
        aggregate = {
          provider = context.provider;
          group = "backend";
        };
        interface = context.interface;
        port = "endpoint";
        value = {
          source = "literal";
          value = endpoint;
        };
      }
    ];
    controllers = [];
  };

  validateConsumerProbe = probe:
    if probe.address != "127.0.0.1"
    then throw "nginx consumer probe must use the IPv4 loopback address"
    else if probe.port < 1024 || probe.port > 65535
    then throw "nginx consumer probe port is outside the unprivileged TCP range"
    else if (probe ? tls_port) != (probe ? tls_credential_path)
    then throw "nginx TLS endpoint and credential path must be declared together"
    else if probe ? tls_port && (probe.tls_port < 1024 || probe.tls_port > 65535)
    then throw "nginx TLS port is outside the unprivileged TCP range"
    else if probe ? tls_credential_path && builtins.match "/var/lib/aos/ability-runtime/credentials/[0-9a-f]{64}-[0-9a-f]{64}\\.view" probe.tls_credential_path == null
    then throw "nginx TLS credential path is outside the protected runtime view"
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
    else if virtualHost.tls && !(virtualHost ? credential_version)
    then throw "nginx TLS contribution requires an opaque credential version"
    else if virtualHost.tls && builtins.match "sha256:[0-9a-f]{64}" virtualHost.credential_version == null
    then throw "nginx TLS credential version is not canonical"
    else if !virtualHost.tls && virtualHost ? credential_version
    then throw "nginx cleartext contribution must not declare a credential version"
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
    storageScope = builtins.substring 0 32 (builtins.hashString "sha256" (builtins.toJSON context.provider));
    storagePath = purpose: "/var/lib/aos/ability-runtime/storage/${storageScope}-${purpose}";
    storagePaths = {
      logs = storagePath "logs";
      runtime = storagePath "runtime";
      state = storagePath "state";
    };
    tlsHosts =
      builtins.filter
      (virtualHost: virtualHost.tls or false)
      virtualHosts;
    tlsVersions = builtins.attrNames (builtins.listToAttrs (builtins.map
      (virtualHost: {
        name = virtualHost.credential_version;
        value = true;
      })
      tlsHosts));

    backendRequestFor = contribution:
      childRequest
      context
      (scope ++ [contribution.slot])
      "backend"
      httpBackend
      [];
    proxyContributions = builtins.filter
      (contribution: contribution.value.proxy_backend or false)
      context.contributions;
    backendRequests = builtins.map backendRequestFor proxyContributions;
    backendEndpointFor = contribution: let
      request = backendRequestFor contribution;
      binding = bindingFor context request;
      selected = outputFrom context binding httpBackend "backend" "endpoint";
    in
      if binding == null || selected == []
      then null
      else if builtins.length selected != 1
      then throw "nginx backend binding produced an ambiguous endpoint"
      else let
        expression = (builtins.head selected).value;
      in
        if expression.source != "literal"
        then throw "nginx backend endpoint must be available during planning"
        else if expression.value == null
        then null
        else validateBackendEndpoint expression.value;
    resolvedVirtualHosts = builtins.map
      (contribution: let
        virtualHost = validateVirtualHost contribution;
      in
        virtualHost
        // (
          if virtualHost.proxy_backend or false
          then {backend_endpoint = backendEndpointFor contribution;}
          else {}
        ))
      context.contributions;
    backendsReady = builtins.all
      (virtualHost: !(virtualHost.proxy_backend or false) || virtualHost.backend_endpoint != null)
      resolvedVirtualHosts;

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
    credentialVersion =
      if !usesTls
      then null
      else if builtins.length tlsVersions != 1
      then throw "nginx TLS virtual hosts must select one credential version"
      else if !(consumerProbe ? tls_port && consumerProbe ? tls_credential_path)
      then throw "nginx TLS service requires an endpoint and protected credential path"
      else builtins.head tlsVersions;
    listeners =
      [
        {
          name = "http";
          port = consumerProbe.port;
        }
      ]
      ++ (
        if usesTls
        then [
          {
            name = "tls";
            port = consumerProbe.tls_port;
          }
        ]
        else []
      );
    endpointRequest =
      (childRequest context scope "endpoint" endpointEffects [])
      // {methods = ["materialize" "observe" "release"];};
    networkPolicyRequest =
      (childRequest context scope "network-policy" networkPolicyEffects [])
      // {
        methods = ["apply" "observe" "remove"];
        guarantees = [loopbackEgressGuarantee loopbackIngressGuarantee];
      };
    storageRequest =
      (childRequest context scope "storage" storageEffects [])
      // {methods = ["ensure" "observe" "release"];};
    requests =
      [configurationRequest]
      ++ (
        if usesTls
        then [credentialRequest]
        else []
      )
      ++ [endpointRequest networkPolicyRequest]
      ++ (
        if serviceRequest == null
        then []
        else [serviceRequest]
      )
      ++ [serviceTerminalRequest storageRequest validationRequest]
      ++ backendRequests;
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
    configurationRevision = "sha256:${builtins.hashString "sha256" (builtins.toJSON resolvedVirtualHosts)}";
    serviceValue = {
      configuration_revision = configurationRevision;
      consumer_endpoint = "${consumerProbe.address}:${builtins.toString consumerProbe.port}";
      unit = "nginx-${context.provider.key}.service";
      virtual_host_count = builtins.length virtualHosts;
      storage_paths = storagePaths;
    };
    serviceRevision = "sha256:${builtins.hashString "sha256" (builtins.toJSON serviceValue)}";
    contributions =
      (
        if backendsReady
        then lowerContribution context configurationRequest "configuration" {
          virtualHosts = resolvedVirtualHosts;
          consumer_content_revision = configurationRevision;
          consumer_controller_revision = serviceRevision;
          consumer_instance = builtins.toJSON context.provider;
          consumer_probe = consumerProbe;
          consumer_storage_paths = storagePaths;
        }
        else []
      )
      ++ (
        if usesTls
        then
          lowerContribution context credentialRequest "credentials" {
            hosts = builtins.map (virtualHost: virtualHost.host) tlsHosts;
            version = credentialVersion;
          }
        else []
      )
      ++ (
        if serviceRequest == null
        then []
        else lowerContribution context serviceRequest "services" serviceValue
      );
    endpointContract = listener: {
      address = consumerProbe.address;
      port = listener.port;
      transport = "tcp";
    };
    endpointRevision = listener: "sha256:${builtins.hashString "sha256" (builtins.toJSON (endpointContract listener))}";
    endpointResource = listener: {
      provider = context.provider;
      key = "${listener.name}-endpoint-${builtins.toString listener.port}";
    };
    policyResource = listener: {
      provider = context.provider;
      key = "${listener.name}-network-policy-${builtins.toString listener.port}";
    };
    storageContract = purpose: {
      cluster = storageScope;
      lifetime =
        if purpose == "runtime"
        then "instance"
        else "persistent";
      owner = "root";
      inherit purpose;
    };
    storageResource = purpose: {
      provider = context.provider;
      key = "${purpose}-storage";
    };
    storageResources =
      builtins.map
      (purpose: {
        resource = storageResource purpose;
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON (storageContract purpose))}";
      })
      ["logs" "runtime" "state"];
    listenerResources =
      builtins.concatMap
      (listener: [
        {
          resource = endpointResource listener;
          revision = endpointRevision listener;
        }
        {
          resource = policyResource listener;
          revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON {
            direction = "ingress";
            endpoint_revision = endpointRevision listener;
            protocol = "tcp";
          })}";
        }
      ])
      listeners;
    backendResources =
      builtins.concatMap
      (contribution: let
        endpoint = backendEndpointFor contribution;
        endpointRevision = "sha256:${builtins.hashString "sha256" (builtins.toJSON endpoint)}";
      in
        if endpoint == null
        then []
        else [
          {
            resource = {
              provider = context.provider;
              key = "backend-${contribution.slot}-endpoint-${builtins.toString endpoint.port}";
            };
            revision = endpointRevision;
          }
          {
            resource = {
              provider = context.provider;
              key = "backend-${contribution.slot}-network-policy-${builtins.toString endpoint.port}";
            };
            revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON {
              direction = "egress";
              endpoint_revision = endpointRevision;
              protocol = "tcp";
            })}";
          }
        ])
      proxyContributions;
    ownedResources =
      [
        {
          resource = {
            provider = context.provider;
            key = "virtual-hosts";
          };
          revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON {
            inherit consumerProbe resolvedVirtualHosts;
          })}";
        }
      ]
      ++ listenerResources
      ++ backendResources
      ++ storageResources;
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
    resources = ownedResources;
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
    controllers =
      builtins.map
      (entry: {
        inherit (entry) resource;
        controller = {
          provider = context.provider;
          group = "nginx";
        };
      })
      ownedResources;
  };

  backendTransition = _context: {
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
  inherit backendCompose backendTransition compose;

  transition = context: let
    storageScope = builtins.substring 0 32 (builtins.hashString "sha256" (builtins.toJSON context.provider));
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
    storage = desiredBinding "storage" storageEffects ["ensure" "observe" "release"];
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
    changesForRequest = requestKey: expectedInterface: requiredMethods: let
      requestBindings = bindingsFor requestKey expectedInterface requiredMethods;
      resources = builtins.concatMap resourcesGrantedBy (builtins.map (entry: entry.binding) requestBindings);
    in
      builtins.filter
      (change: builtins.elem change.resource resources)
      context.changes;
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
    endpointChanges = changesForRequest "endpoint" endpointEffects ["materialize" "observe" "release"];
    networkPolicyChanges = changesForRequest "network-policy" networkPolicyEffects ["apply" "observe" "remove"];
    storageChanges = changesForRequest "storage" storageEffects ["ensure" "observe" "release"];
    endpointAvailable = builtins.filter (change: change.kind != "remove") endpointChanges;
    endpointRemoved = builtins.filter (change: change.kind == "remove") endpointChanges;
    networkPolicyAvailable = builtins.filter (change: change.kind != "remove") networkPolicyChanges;
    networkPolicyRemoved = builtins.filter (change: change.kind == "remove") networkPolicyChanges;
    endpointChanged = createdOrUpdated endpointChanges;
    networkPolicyChanged = createdOrUpdated networkPolicyChanges;
    storageAvailable = builtins.filter (change: change.kind != "remove") storageChanges;
    storageRemoved = builtins.filter (change: change.kind == "remove") storageChanges;
    storageChanged = createdOrUpdated storageChanges;
    owned =
      builtins.filter
      (change: change.resource.provider == context.provider)
      context.changes;
    virtualHostChanges = builtins.filter (change: change.resource.key == "virtual-hosts") owned;
    retained = builtins.filter (change: change.kind != "remove") virtualHostChanges;
    removed = builtins.filter (change: change.kind == "remove") virtualHostChanges;
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
    needsValidation = configurationChanged != [] || credentialChanged != [] || storageChanged != [];
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
    needsConvergence =
      needsValidation
      || serviceChanged != []
      || endpointChanged != []
      || networkPolicyChanged != []
      || storageChanged != [];
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
    validationInputs = candidate: credentialViews: storagePaths: {
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
        storage_paths = storagePaths;
      };
    };
    controllerFor = resource: let
      controllers = builtins.filter (entry: entry.resource == resource) context.controllers;
    in
      if builtins.length controllers == 1
      then (builtins.head controllers).controller
      else throw "nginx transition requires one resource controller";
    terminalFor = authorityRole: requestKey: expectedInterface: resource: method: access: let
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
              && entry.binding.request.key == requestKey
            else
              entry.authority.source_request.consumer
              == context.provider
              && entry.authority.source_request.key == requestKey
          )
          && entry.binding.interface == expectedInterface
          && builtins.elem method entry.binding.caller_grant.methods
          && builtins.length (builtins.filter
            (permission:
              permission.resource
              == resource
              && (
                permission.access
                == access
                || (access == "read" && permission.access == "exclusive-write")
              )
              && builtins.elem method permission.operations)
            entry.binding.caller_grant.resources)
          == 1)
        context.authorized_bindings;
    in
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "nginx transition requires one authorized ${authorityRole} ${requestKey}.${method} binding for ${resource.key}";
    literal = value: {
      source = "literal";
      inherit value;
    };
    object = fields: {
      source = "object";
      inherit fields;
    };
    operationResult = operation: output: {
      source = "operation-result";
      reference = {
        producer = node operation;
        inherit output;
      };
    };
    listenerFromResource = kind: resource: let
      matched = builtins.match "(http|tls|backend-[-A-Za-z0-9._]+)-${kind}-([0-9]+)" resource.key;
    in
      if matched == null
      then throw "nginx transition received malformed ${kind} resource '${resource.key}'"
      else {
        name = builtins.elemAt matched 0;
        port = builtins.fromJSON (builtins.elemAt matched 1);
      };
    endpointResourceForPolicy = resource: {
      inherit (resource) provider;
      key = builtins.replaceStrings ["-network-policy-"] ["-endpoint-"] resource.key;
    };
    policyDirection = resource:
      if builtins.match "backend-.*-network-policy-[0-9]+" resource.key != null
      then "egress"
      else "ingress";
    storagePurpose = resource: let
      matched = builtins.match "(logs|runtime|state)-storage" resource.key;
    in
      if matched == null
      then throw "nginx transition received malformed storage resource '${resource.key}'"
      else builtins.head matched;
    changeFor = changes: resource: let
      selected = builtins.filter (change: change.resource == resource) changes;
    in
      if builtins.length selected == 1
      then builtins.head selected
      else throw "nginx transition requires exactly one visible change for ${resource.key}";
    selectedAction = change: mutation: observation:
      if
        builtins.elem change.kind [
          "create"
          "update"
          "reconcile-stopped"
          "reconcile-divergent"
        ]
      then mutation
      else if change.kind == "unchanged"
      then observation
      else throw "nginx transition cannot provision ${change.resource.key} from '${change.kind}'";
    nativeOperation = {
      authorityRole,
      requestKey,
      expectedInterface,
      resource,
      method,
      family,
      phase,
      inputPhase,
      inputs,
      access,
    }: let
      binding = terminalFor authorityRole requestKey expectedInterface resource method access;
    in {
      key = scopedKey "${method}-${resource.key}";
      branch_context = [];
      binding = binding.id;
      authority = "caller";
      interface = binding.interface;
      inherit method family phase inputs;
      input_phase = inputPhase;
      target = {
        interface = binding.interface;
        inherit resource;
        operations = [method];
        lifetime = "instance";
      };
      preconditions = [];
      accesses = [
        {
          inherit resource;
          mode = access;
        }
      ];
      controller = controllerFor resource;
      deadline = operationDeadline;
      recovery = {
        retry = {
          kind = "bounded";
          max_attempts = 2;
          backoff_millis = 0;
        };
        reconcile = {
          interface = binding.interface;
          inherit method;
        };
        cancel = {
          interface = binding.interface;
          inherit method;
        };
        compensate = null;
      };
    };
    storageOperation = authorityRole: change: let
      purpose = storagePurpose change.resource;
      method =
        if authorityRole == "teardown"
        then "release"
        else selectedAction change "ensure" "observe";
    in
      nativeOperation {
        inherit authorityRole method;
        requestKey = "storage";
        expectedInterface = storageEffects;
        resource = change.resource;
        family = {
          kind = "host-storage";
          action = method;
        };
        phase =
          if authorityRole == "teardown"
          then "converging"
          else "preparing";
        inputPhase = "planning";
        inputs = literal {
          cluster = storageScope;
          lifetime =
            if purpose == "runtime"
            then "instance"
            else "persistent";
          owner = "root";
          inherit purpose;
        };
        access =
          if method == "observe"
          then "read"
          else "exclusive-write";
      };
    endpointOperation = authorityRole: change: let
      listener = listenerFromResource "endpoint" change.resource;
      method =
        if authorityRole == "teardown"
        then "release"
        else selectedAction change "materialize" "observe";
    in
      nativeOperation {
        inherit authorityRole method;
        requestKey = "endpoint";
        expectedInterface = endpointEffects;
        resource = change.resource;
        family = {
          kind = "network-endpoint";
          action = method;
        };
        phase =
          if authorityRole == "teardown"
          then "converging"
          else "preparing";
        inputPhase = "planning";
        inputs = literal {
          address = "127.0.0.1";
          inherit (listener) port;
          transport = "tcp";
        };
        access =
          if method == "observe"
          then "read"
          else "exclusive-write";
      };
    networkPolicyOperation = authorityRole: change: let
      endpointResource = endpointResourceForPolicy change.resource;
      endpointChange = changeFor endpointChanges endpointResource;
      endpointMethod =
        if authorityRole == "teardown"
        then "release"
        else selectedAction endpointChange "materialize" "observe";
      method =
        if authorityRole == "teardown"
        then "remove"
        else selectedAction change "apply" "observe";
    in
      nativeOperation {
        inherit authorityRole method;
        requestKey = "network-policy";
        expectedInterface = networkPolicyEffects;
        resource = change.resource;
        family = {
          kind = "host-network-policy";
          action = method;
        };
        phase =
          if authorityRole == "teardown"
          then "converging"
          else "publishing";
        inputPhase =
          if authorityRole == "teardown"
          then "planning"
          else "runtime";
        inputs =
          if authorityRole == "teardown"
          then
            literal {
              direction = policyDirection change.resource;
              endpoint = null;
              protocol = "tcp";
            }
          else
            object {
              direction = literal (policyDirection change.resource);
              endpoint = operationResult "${endpointMethod}-${endpointResource.key}" "endpoint";
              protocol = literal "tcp";
            };
        access =
          if method == "observe"
          then "read"
          else "exclusive-write";
      };
    storagePathInputs = let
      pathFor = purpose: let
        selected =
          builtins.filter
          (change: storagePurpose change.resource == purpose)
          storageAvailable;
        change =
          if builtins.length selected == 1
          then builtins.head selected
          else throw "nginx transition requires one ${purpose} storage resource";
        method = selectedAction change "ensure" "observe";
      in
        operationResult "${method}-${change.resource.key}" "path";
    in
      object {
        logs = pathFor "logs";
        runtime = pathFor "runtime";
        state = pathFor "state";
      };
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
      inputs = validationInputs true credentialViewInputs storagePathInputs;
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
      inputs = validationInputs true [] (literal null);
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
      inputs = validationInputs false [] (literal null);
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
    validationOnlyEdges =
      if needsValidation && configurationChanged == []
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
    endpointOperations =
      if needsConvergence
      then builtins.map (endpointOperation "desired") endpointAvailable
      else [];
    networkPolicyOperations =
      if needsConvergence
      then builtins.map (networkPolicyOperation "desired") networkPolicyAvailable
      else [];
    storageOperations =
      if needsConvergence
      then builtins.map (storageOperation "desired") storageAvailable
      else [];
    storageValidationEdges =
      if needsValidation
      then
        builtins.concatMap
        (change: let
          method = selectedAction change "ensure" "observe";
        in
          builtins.map
          (association: {
            from = node "${method}-${change.resource.key}";
            to = node "validate-${association.resource.key}";
            kind = "data";
          })
          associationChanges)
        storageAvailable
      else [];
    endpointPolicyEdges =
      if needsConvergence
      then
        builtins.concatMap
        (change: let
          endpointResource = endpointResourceForPolicy change.resource;
          endpointChange = changeFor endpointChanges endpointResource;
          endpointMethod = selectedAction endpointChange "materialize" "observe";
          policyMethod = selectedAction change "apply" "observe";
        in [
          {
            from = node "${endpointMethod}-${endpointResource.key}";
            to = node "${policyMethod}-${change.resource.key}";
            kind = "data";
          }
          {
            from = node "${policyMethod}-${change.resource.key}";
            to = node "${serviceAction}-${serviceResource.key}";
            kind = "required-success";
          }
        ])
        networkPolicyAvailable
      else [];
    backendCommunicationEdges =
      if needsConvergence
      then
        builtins.map
        (change: let
          endpointResource = endpointResourceForPolicy change.resource;
          endpointChange = changeFor endpointChanges endpointResource;
          endpointMethod = selectedAction endpointChange "materialize" "observe";
        in {
          from = node "${endpointMethod}-${endpointResource.key}";
          to = node "observe-${serviceResource.key}";
          kind = "communication";
        })
        (builtins.filter
          (change: policyDirection change.resource == "egress")
          networkPolicyAvailable)
      else [];
    endpointReleaseOperations = builtins.map (endpointOperation "teardown") endpointRemoved;
    networkPolicyRemoveOperations = builtins.map (networkPolicyOperation "teardown") networkPolicyRemoved;
    storageReleaseOperations = builtins.map (storageOperation "teardown") storageRemoved;
    networkTeardownEdges =
      builtins.concatMap
      (change: let
        endpointResource = endpointResourceForPolicy change.resource;
        endpointChange = changeFor endpointChanges endpointResource;
        exposureClosedBy =
          if removed != []
          then "stop-${serviceResource.key}"
          else "observe-${serviceResource.key}";
      in [
        {
          from = node exposureClosedBy;
          to = node "remove-${change.resource.key}";
          kind = "required-success";
        }
        {
          from = node "remove-${change.resource.key}";
          to = node "release-${endpointChange.resource.key}";
          kind = "required-success";
        }
      ])
      networkPolicyRemoved;
    storageTeardownEdges =
      builtins.map
      (change: {
        from =
          if removed != []
          then node "stop-${serviceResource.key}"
          else node "observe-${serviceResource.key}";
        to = node "release-${change.resource.key}";
        kind = "required-success";
      })
      storageRemoved;
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
          ++ endpointOperations
          ++ networkPolicyOperations
          ++ storageOperations
          ++ endpointReleaseOperations
          ++ networkPolicyRemoveOperations
          ++ storageReleaseOperations
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
        (
          convergenceEdges
          ++ validationOnlyEdges
          ++ endpointPolicyEdges
          ++ backendCommunicationEdges
          ++ storageValidationEdges
          ++ teardownEdges
          ++ networkTeardownEdges
          ++ storageTeardownEdges
        );
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
    else if
      associationChanges
      == []
      && removed == []
      && credentialRemoved == []
      && endpointRemoved == []
      && networkPolicyRemoved == []
      && storageRemoved == []
    then
      fragment
      // {
        operations = [];
        imports = [];
        links = [];
      }
    else fragment;
}
