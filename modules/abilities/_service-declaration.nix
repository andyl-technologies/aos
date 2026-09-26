##! Expands one manager-neutral service declaration into feature requests.
{
  serviceInterfaces,
  serviceTypes,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  featureInterfaces = {
    lifecycle = serviceInterfaces.lifecycle;
    template_definition = serviceInterfaces.templateDefinition;
    dependencies = serviceInterfaces.dependencies;
    conditions = serviceInterfaces.conditions;
    instantiation = serviceInterfaces.instantiation;
    manager_identity = serviceInterfaces.managerIdentity;
    supervision = serviceInterfaces.supervision;
    readiness = serviceInterfaces.readiness;
    reload = serviceInterfaces.reload;
    termination = serviceInterfaces.termination;
    watchdog = serviceInterfaces.watchdog;
    start_policy = serviceInterfaces.startPolicy;
    failure_policy = serviceInterfaces.failurePolicy;
    concurrency = serviceInterfaces.concurrency;
    scheduling = serviceInterfaces.scheduling;
    resources = serviceInterfaces.resources;
    environment = serviceInterfaces.environment;
    directories = serviceInterfaces.directories;
    activation = serviceInterfaces.activation;
    credentials = serviceInterfaces.credentials;
    configuration = serviceInterfaces.configuration;
    storage = serviceInterfaces.storage;
    socket_activation = serviceInterfaces.socketActivation;
    logging = serviceInterfaces.logging;
    terminal = serviceInterfaces.terminal;
    identity = serviceInterfaces.identity;
    isolation = serviceInterfaces.isolation;
  };

  uniqueBy = field: values:
    builtins.length values
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value.${field};
        value = true;
      })
      values)));
  uniqueGuarantees = values:
    builtins.attrValues (builtins.listToAttrs (builtins.map (guarantee: {
        name = guarantee;
        value = guarantee;
      })
      values));

  normalizeCredentialReference = reference:
    if !serviceTypes.credentialReference.check reference
    then throw "credential reference does not match the canonical credential reference type"
    else {
      resource = reference.resource or null;
      name = reference.name or null;
      scope = reference.scope or "system";
      encrypted = reference.encrypted or false;
    };
  credentialReferenceConfigured = reference: let
    normalized = normalizeCredentialReference reference;
  in
    normalized.resource != null || normalized.name != null;

  checkedMethods = interface: methods: let
    uniqueMethods = builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = true;
      })
      methods));
  in
    if methods == []
    then throw "a producer requirement must select at least one interface method"
    else if builtins.length methods != builtins.length uniqueMethods
    then throw "producer requirement methods must be unique"
    else if !builtins.all (name: builtins.elem name interface.methods) methods
    then throw "producer requirement methods must belong to the selected interface"
    else builtins.sort builtins.lessThan methods;

  canonicalInterface = interface:
    if interface ? identity && interface ? methods
    then interface
    else let
      document = interfaceDocumentFromDeclaration interface.declaration;
    in
      interface
      // {
        inherit document;
        identity = interfaceIdentity document;
        methods = builtins.attrNames interface.declaration.methods;
        requestType = interface.declaration.requestType;
      };

  validate = serviceTypes: declaration: let
    normalizedDeclaration = serviceTypes.serviceDeclaration.merge ["service" declaration.service] [
      {
        file = "<service declaration>";
        value = declaration;
      }
    ];
    lifecycle = normalizedDeclaration.lifecycle;
    startCommandCount = builtins.length lifecycle.start;
    reload = normalizedDeclaration.reload or null;
    instantiation = normalizedDeclaration.instantiation or null;
    managerIdentity = normalizedDeclaration.manager_identity or null;
    supervision = normalizedDeclaration.supervision or null;
    startPolicy = normalizedDeclaration.start_policy or null;
    resources = normalizedDeclaration.resources or null;
    environment = normalizedDeclaration.environment or null;
    directories = normalizedDeclaration.directories or null;
    activation = normalizedDeclaration.activation or null;
    readiness = normalizedDeclaration.readiness or null;
    identity = normalizedDeclaration.identity or null;
    credentials = normalizedDeclaration.credentials or null;
    configuration = normalizedDeclaration.configuration or null;
    storage = normalizedDeclaration.storage or null;
    socketActivation = normalizedDeclaration.socket_activation or null;
    logging = normalizedDeclaration.logging or null;
    terminal = normalizedDeclaration.terminal or null;
    reloadValid =
      reload
      == null
      || (
        if reload.strategy == "command"
        then reload.commands != [] && (reload.signal or null) == null
        else if reload.strategy == "signal"
        then reload.commands == [] && (reload.signal or null) != null
        else reload.commands == [] && (reload.signal or null) == null
      );
    instantiationValid =
      instantiation
      == null
      || (
        if instantiation.kind == "singleton"
        then builtins.attrNames instantiation == ["kind"]
        else if instantiation.kind == "template"
        then builtins.attrNames instantiation == ["kind" "template"]
        else
          instantiation.kind
          == "instance"
          && builtins.attrNames instantiation == ["instance" "kind" "template_resource"]
      );
    templateIsStatic =
      instantiation
      == null
      || instantiation.kind != "template"
      || !normalizedDeclaration.enabled;
    supervisionValid =
      supervision
      == null
      || (
        (supervision.startup_protocol != "notification" || supervision.notification_access != "none")
        && (supervision.startup_protocol != "bus-name" || (supervision.bus_name or null) != null)
        && (supervision.startup_protocol != "process" || supervision.notification_access == "none")
      );
    startPolicyValid =
      startPolicy
      == null
      || ((startPolicy.rate_interval_millis or null) == null) == ((startPolicy.rate_burst or null) == null);
    maximumResourceValue = quantity:
      if quantity != null && quantity.kind == "maximum"
      then quantity.value
      else null;
    memoryRangeValid =
      resources
      == null
      || (let
        high = maximumResourceValue (resources.memory_high_bytes or null);
        maximum = maximumResourceValue (resources.memory_max_bytes or null);
      in
        high == null || maximum == null || high <= maximum);
    directoriesValid =
      directories
      == null
      || builtins.length directories.managed
      == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (directory: {
          name = "${directory.purpose}:${directory.path}";
          value = true;
        })
        directories.managed)));
    environmentValid =
      environment
      == null
      || environment.search_path == []
      || !(builtins.hasAttr "PATH" environment.variables);
    activationValid =
      activation
      == null
      || (
        uniqueBy "name" activation.bindings
        && builtins.all
        (binding:
          builtins.elem binding.relationship [
            "resource-triggers-service"
            "service-depends-on-resource"
            "service-member-of-resource"
          ])
        activation.bindings
      );
    readinessValid =
      readiness
      == null
      || (
        if readiness.mechanism == "process-signal"
        then readiness.signal_scope != "none"
        else readiness.signal_scope == "none"
      );
    readinessExecutionValid =
      readiness
      == null
      || readiness.mechanism != "process-signal"
      || lifecycle.execution_model == "foreground";
    successfulExitValid =
      readiness
      == null
      || readiness.mechanism != "successful-exit"
      || lifecycle.execution_model == "oneshot";
    socketReadinessValid =
      readiness
      == null
      || readiness.mechanism != "socket-accepting"
      || (socketActivation != null && socketActivation.sockets != []);
    identityValid =
      identity
      == null
      || !identity.ephemeral
      || ((identity.principal or null) == null && (identity.primary_group or null) == null);
    credentialsValid =
      credentials
      == null
      || uniqueBy "name" credentials.views;
    configurationValid =
      configuration
      == null
      || uniqueBy "name" configuration.views;
    storageValid =
      storage
      == null
      || uniqueBy "name" storage.mounts;
    socketsValid =
      socketActivation
      == null
      || (
        let
          socketNames = builtins.map (socket: socket.name) socketActivation.sockets;
          serviceDependencies = socketActivation.service_dependencies or {};
          localReferences =
            (serviceDependencies.after or [])
            ++ (serviceDependencies.binds_to or [])
            ++ (serviceDependencies.requires or [])
            ++ (serviceDependencies.wants or [])
            ++ builtins.concatMap
            (socket: (socket.after or []) ++ (socket.binds_to or []))
            socketActivation.sockets;
        in
          uniqueBy "name" socketActivation.sockets
          && builtins.all (name: builtins.elem name socketNames) localReferences
          && builtins.all
          (socket:
            !(builtins.elem socket.name (socket.after or []))
            && !(builtins.elem socket.name (socket.binds_to or [])))
          socketActivation.sockets
          && builtins.length (builtins.filter
            (socket: (socket.manager_name or null) != null)
            socketActivation.sockets)
          == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map
            (socket: {
              name = socket.manager_name;
              value = true;
            })
            (builtins.filter
              (socket: (socket.manager_name or null) != null)
              socketActivation.sockets))))
      );
    managerIdentityValid =
      managerIdentity
      == null
      || (
        (
          instantiation
          == null
          || builtins.elem instantiation.kind ["singleton" "template"]
        )
        && !(builtins.elem managerIdentity.name managerIdentity.aliases)
        && builtins.length managerIdentity.aliases
        == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map
          (name: {
            inherit name;
            value = true;
          })
          managerIdentity.aliases)))
      );
    loggingValid =
      logging
      == null
      || builtins.length logging.directories
      == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
          inherit name;
          value = true;
        })
        logging.directories)));
    terminalValid =
      terminal
      == null
      || !terminal.start_when_idle
      || (
        lifecycle.execution_model
        == "foreground"
        && supervision == null
        && readiness != null
        && readiness.mechanism == "process-running"
      );
  in
    if !serviceTypes.serviceDeclaration.check normalizedDeclaration
    then throw "service declaration '${declaration.service or "<unknown>"}' does not match the canonical service type"
    else if startCommandCount == 0
    then throw "service '${declaration.service}' must declare at least one start command"
    else if lifecycle.execution_model != "oneshot" && startCommandCount != 1
    then throw "service '${declaration.service}' must declare exactly one start command unless it is oneshot"
    else if !reloadValid
    then throw "service '${declaration.service}' reload strategy has inconsistent commands or signal"
    else if !instantiationValid
    then throw "service '${declaration.service}' instantiation kind has inconsistent template or instance fields"
    else if !templateIsStatic
    then throw "service '${declaration.service}' template definition must be disabled until a concrete instance is declared"
    else if !supervisionValid
    then throw "service '${declaration.service}' supervision protocol has inconsistent notification access or bus name"
    else if !startPolicyValid
    then throw "service '${declaration.service}' start rate interval and burst must be declared together"
    else if !memoryRangeValid
    then throw "service '${declaration.service}' finite memory high limit must not exceed its maximum"
    else if !directoriesValid
    then throw "service '${declaration.service}' has duplicate managed directory paths"
    else if !environmentValid
    then throw "service '${declaration.service}' environment.variables cannot define PATH when search_path is non-empty"
    else if !activationValid
    then throw "service '${declaration.service}' has duplicate or inconsistent activation relationships"
    else if !readinessValid
    then throw "service '${declaration.service}' process-signal readiness requires a signaling scope, and other mechanisms must not set one"
    else if !readinessExecutionValid
    then throw "service '${declaration.service}' process-signal readiness requires foreground execution"
    else if !successfulExitValid
    then throw "service '${declaration.service}' successful-exit readiness requires oneshot execution"
    else if !socketReadinessValid
    then throw "service '${declaration.service}' socket readiness requires at least one socket activation declaration"
    else if !identityValid
    then throw "service '${declaration.service}' ephemeral identity cannot also declare a principal or primary group"
    else if !credentialsValid
    then throw "service '${declaration.service}' has duplicate credential view names"
    else if !configurationValid
    then throw "service '${declaration.service}' has duplicate configuration view names"
    else if !storageValid
    then throw "service '${declaration.service}' has duplicate storage mount names"
    else if !socketsValid
    then throw "service '${declaration.service}' has duplicate socket names, invalid local socket dependencies, or duplicate public manager names"
    else if !terminalValid
    then throw "service '${declaration.service}' can start when the terminal is idle only with foreground process-running readiness and no alternate supervision protocol"
    else if !managerIdentityValid
    then throw "service '${declaration.service}' has an invalid public manager identity"
    else if !loggingValid
    then throw "service '${declaration.service}' has duplicate log directory names"
    else
      declaration
      // {
        lifecycle = {configuration_change_action = "restart";} // declaration.lifecycle;
      }
      // (
        if storage == null
        then {}
        else {
          storage =
            storage
            // {
              mounts = builtins.map (mount: {ownership = "provider";} // mount) storage.mounts;
            };
        }
      );

  requirementFor = interface: methods: guarantees: {
    description = interface.declaration.description;
    inherit (interface.identity) abi descriptor;
    interface = interface.identity.name;
    inherit methods;
    inherit guarantees;
    strength = "required";
    fallback = null;
  };

  featureRequest = {
    key,
    requirementAlias,
    description,
    interface,
    parameters,
    abi ? 1,
    descriptor ? null,
    methods ? ["observe"],
    guarantees ? [],
  }: {
    inherit key parameters requirementAlias;
    requirement = {
      inherit description interface abi descriptor methods guarantees;
      strength = "required";
      fallback = null;
    };
  };

  requestParameters = declaration: feature: let
    featureValue =
      if feature == "template_definition"
      then declaration.lifecycle
      else if feature == "instantiation"
      then {selection = declaration.instantiation;}
      else declaration.${feature};
  in
    {inherit (declaration) service;}
    // (
      if feature == "template_definition"
      then {}
      else {inherit (declaration) enabled;}
    )
    // featureValue;

  structuredSource = {
    format,
    valueType,
    value,
  }: let
    rootSchema = valueType._abilitySchema or (throw "structured configuration valueType must be a portable ability type");
    keySegment = name: {
      kind = "key";
      value = name;
    };
    indexSegment = index: {
      kind = "index";
      value = index;
    };
    unwrapRefined = schema:
      if schema.kind == "refined"
      then unwrapRefined schema.value
      else schema;
    unwrapOptional = schema: let
      concrete = unwrapRefined schema;
    in
      if concrete.kind == "optional"
      then unwrapRefined concrete.value
      else concrete;
    isOptional = schema:
      (unwrapRefined schema).kind == "optional";
    scalarKind = schema: let
      concrete = unwrapOptional schema;
    in
      if concrete.kind == "boolean"
      then "boolean"
      else if concrete.kind == "integer"
      then "integer"
      else if concrete.kind == "string" && concrete.syntax == "execution-path-v1"
      then "execution-path"
      else if builtins.elem concrete.kind ["string" "string-enum"]
      then "string"
      else throw "deferred structured configuration leaves must have Boolean, integer, or string schemas";
    nodesAt = path: schema: current: let
      concrete = unwrapOptional schema;
    in
      if current == null && isOptional schema
      then
        if format == "toml"
        then []
        else [
          {
            kind = "null";
            inherit path;
          }
        ]
      else if builtins.isAttrs current && (current._type or null) == "aos-request-output-reference"
      then [
        {
          kind = scalarKind concrete;
          inherit path;
          value = current;
        }
      ]
      else if concrete.kind == "boolean"
      then [
        {
          kind = "boolean";
          inherit path;
          value = current;
        }
      ]
      else if concrete.kind == "integer"
      then [
        {
          kind = "integer";
          inherit path;
          value = current;
        }
      ]
      else if builtins.elem concrete.kind ["string" "string-enum"]
      then [
        {
          kind = scalarKind concrete;
          inherit path;
          value = current;
        }
      ]
      else if concrete.kind == "list"
      then
        [
          {
            kind = "array";
            inherit path;
          }
        ]
        ++ builtins.concatLists (builtins.genList
          (index: nodesAt (path ++ [(indexSegment index)]) concrete.element (builtins.elemAt current index))
          (builtins.length current))
      else if concrete.kind == "map"
      then
        [
          {
            kind = "object";
            inherit path;
          }
        ]
        ++ builtins.concatLists (builtins.map
          (name: nodesAt (path ++ [(keySegment name)]) concrete.value current.${name})
          (builtins.attrNames current))
      else if builtins.elem concrete.kind ["record" "document-record"]
      then
        [
          {
            kind = "object";
            inherit path;
          }
        ]
        ++ builtins.concatLists (builtins.map
          (name: nodesAt (path ++ [(keySegment name)]) concrete.fields.${name} current.${name})
          (builtins.attrNames current))
      else if concrete.kind == "tagged-union"
      then nodesAt path concrete.variants.${current.${concrete.tag}} current
      else throw "structured configuration values require Boolean, integer, string, list, map, record, tagged-union, or optional schemas";
  in {
    kind = "structured-value";
    inherit format;
    document = nodesAt [] rootSchema value;
  };

  valueFromStructuredSource = source: let
    valueForNode = node:
      if node.kind == "object"
      then {}
      else if node.kind == "array"
      then []
      else if node.kind == "null"
      then null
      else node.value;
    setAt = path: value: current:
      if path == []
      then value
      else let
        segment = builtins.head path;
        remaining = builtins.tail path;
      in
        if segment.kind == "key"
        then
          (
            if builtins.isAttrs current
            then current
            else {}
          )
          // {
            ${segment.value} = setAt remaining value (
              if builtins.isAttrs current
              then current.${segment.value} or null
              else null
            );
          }
        else if segment.kind == "index"
        then let
          list =
            if builtins.isList current
            then current
            else [];
          length = builtins.length list;
          targetLength =
            if length > segment.value
            then length
            else segment.value + 1;
        in
          builtins.genList
          (index:
            if index == segment.value
            then
              setAt remaining value (
                if index < length
                then builtins.elemAt list index
                else null
              )
            else if index < length
            then builtins.elemAt list index
            else null)
          targetLength
        else throw "structured configuration path has an unsupported segment";
  in
    if source.kind != "structured-value"
    then throw "configuration source is not a structured value"
    else
      builtins.foldl'
      (value: node: setAt node.path (valueForNode node) value)
      null
      source.document;

  # Package capability declarations remain visible when their configured
  # instances and requests are disabled.
  splitDefinition = definition: let
    declarationFields = ["guarantees" "interfaces" "implementations" "requirementTemplates"];
    declarations = builtins.listToAttrs (builtins.concatMap (name:
      if builtins.hasAttr name definition
      then [
        {
          inherit name;
          value = definition.${name};
        }
      ]
      else [])
    declarationFields);
  in {
    inherit declarations;
    configured = builtins.removeAttrs definition declarationFields;
  };

  forService = {
    serviceTypes,
    consumerInstance,
    declaration,
    featureRequests ? [],
  }: let
    checked = validate serviceTypes declaration;
    staticTemplate =
      (checked.instantiation or null)
      != null
      && checked.instantiation.kind == "template";
    enabledFeatures =
      builtins.filter
      (feature:
        (feature == "lifecycle" && !staticTemplate)
        || (feature == "template_definition" && staticTemplate)
        || (
          !builtins.elem feature ["lifecycle" "template_definition"]
          && (checked.${feature} or null) != null
        ))
      (builtins.attrNames featureInterfaces);
    methodsFor = feature:
      if feature == "lifecycle" && (checked.reload or null) == null
      then builtins.filter (method: method != "reload") featureInterfaces.lifecycle.methods
      else featureInterfaces.${feature}.methods;
    guaranteesFor = feature:
      if feature == "conditions"
      then
        uniqueGuarantees (builtins.map
          (condition: featureInterfaces.conditions.guaranteesByKind.${condition.kind})
          checked.conditions.all)
      else if feature == "lifecycle" && (checked.instantiation or null) != null && checked.instantiation.kind == "instance"
      then [featureInterfaces.lifecycle.guaranteesByKind.instance]
      else [];
    coreRequirementTemplates = builtins.listToAttrs (builtins.map (feature: {
        name = "${checked.service}-${featureInterfaces.${feature}.alias}";
        value = requirementFor featureInterfaces.${feature} (methodsFor feature) (guaranteesFor feature);
      })
      enabledFeatures);
    coreRequests = builtins.listToAttrs (builtins.map (feature: {
        name = "${checked.service}-${feature}";
        value = {
          requirement = "${checked.service}-${featureInterfaces.${feature}.alias}";
          consumer = consumerInstance;
          scope = [checked.service];
          parameters = requestParameters checked feature;
        };
      })
      enabledFeatures);
    featureKeys = builtins.map (feature: feature.key) featureRequests;
    requirementAliases = builtins.map (feature: feature.requirementAlias) featureRequests;
    externalRequirementTemplates = builtins.listToAttrs (builtins.map (feature: {
        name = "${checked.service}-${feature.requirementAlias}";
        value = feature.requirement;
      })
      featureRequests);
    externalRequests = builtins.listToAttrs (builtins.map (feature: {
        name = "${checked.service}-${feature.key}";
        value = {
          requirement = "${checked.service}-${feature.requirementAlias}";
          consumer = consumerInstance;
          scope = [checked.service];
          parameters =
            {
              inherit (checked) service enabled;
            }
            // feature.parameters;
        };
      })
      featureRequests);
    definition = {
      requirementTemplates = coreRequirementTemplates // externalRequirementTemplates;
      requests = coreRequests // externalRequests;
    };
  in
    if !uniqueBy "value" (builtins.map (value: {inherit value;}) featureKeys)
    then throw "service '${checked.service}' has duplicate external feature keys"
    else if !uniqueBy "value" (builtins.map (value: {inherit value;}) requirementAliases)
    then throw "service '${checked.service}' has duplicate external feature requirements"
    else definition;

  ## Derives a concrete instance from one checked static template declaration.
  instanceOf = {
    serviceTypes,
    template,
    service,
    instance,
    enabled ? true,
  }: let
    checkedTemplate = validate serviceTypes template;
    templateRequest = "${checkedTemplate.service}-template_definition";
    derived =
      builtins.removeAttrs checkedTemplate ["service" "enabled" "instantiation"]
      // {
        inherit service enabled;
        instantiation = {
          kind = "instance";
          inherit instance;
          template_resource = {
            _type = "aos-request-output-reference";
            request = templateRequest;
            output = "resource";
          };
        };
      };
  in
    if (checkedTemplate.instantiation or null) == null || checkedTemplate.instantiation.kind != "template"
    then throw "service template instance source must be a static template declaration"
    else validate serviceTypes derived;

  forConfiguration = {
    serviceTypes,
    consumerInstance,
    declaration,
  }: let
    source = declaration.source or {};
    credentialFragments =
      builtins.filter
      (fragment: (fragment.kind or null) == "credential-content")
      (source.fragments or []);
    protectedMode = builtins.elem (declaration.mode or null) ["0400" "0600"];
    credentialPairsValid = builtins.all (fragment: let
      resource = fragment.resource or {};
      path = fragment.path or {};
    in
      (resource._type or null)
      == "aos-request-output-reference"
      && (path._type or null) == "aos-request-output-reference"
      && resource.request == path.request
      && resource.output == "resource"
      && path.output == "credential-path")
    credentialFragments;
    checked = serviceTypes.configurationMaterialization.merge ["managed configuration" declaration.name] [
      {
        file = "<managed configuration declaration>";
        value = declaration;
      }
    ];
    validated =
      if credentialFragments != [] && !protectedMode
      then throw "managed configuration '${declaration.name}' containing credentials must use mode 0400 or 0600"
      else if !credentialPairsValid
      then throw "managed configuration '${declaration.name}' must pair each credential resource and path from one delivery request"
      else checked;
    interface = serviceInterfaces.managedConfiguration;
    definition = {
      requirementTemplates.${interface.alias} = requirementFor interface interface.methods [];
      requests.${validated.name} = {
        requirement = interface.alias;
        consumer = consumerInstance;
        scope = [validated.name];
        parameters = validated;
      };
    };
  in
    definition;

  forProducers = {
    consumerInstance,
    interface,
    producers,
    methods ? null,
  }: let
    selectedInterface = canonicalInterface interface;
    selectedMethods = checkedMethods selectedInterface (
      if methods == null
      then selectedInterface.methods
      else methods
    );
    storageViewPairsValid =
      selectedInterface.alias
      != "storage-view"
      || builtins.all (producer: let
        source = producer.parameters.source or {};
        sourcePath = producer.parameters.source_path or {};
      in
        (source._type or null)
        == "aos-request-output-reference"
        && (sourcePath._type or null) == "aos-request-output-reference"
        && source.request == sourcePath.request
        && source.output == "resource"
        && sourcePath.output == "planned-path")
      producers;
    definition =
      if !uniqueBy "key" producers
      then throw "producer request keys must be unique"
      else if !storageViewPairsValid
      then throw "storage views must pair resource and planned-path outputs from one allocation request"
      else {
        requirementTemplates.${selectedInterface.alias} = requirementFor selectedInterface selectedMethods [];
        requests = builtins.listToAttrs (builtins.map (producer: {
            name = producer.key;
            value = {
              requirement = selectedInterface.alias;
              consumer = consumerInstance;
              scope = [producer.key];
              parameters = producer.parameters;
            };
          })
          producers);
      };
  in
    definition;

  forProducer = args:
    forProducers (
      {
        inherit (args) consumerInstance interface;
        producers = [
          {
            inherit (args) key parameters;
          }
        ];
      }
      // (
        if args ? methods
        then {inherit (args) methods;}
        else {}
      )
    );

  forCredentialReferences = {
    consumerInstance,
    references,
  }: let
    checkedReferences = builtins.map (entry:
      entry
      // {
        reference = normalizeCredentialReference entry.reference;
      })
    references;
    configuredReferences =
      builtins.filter
      (entry: credentialReferenceConfigured entry.reference)
      checkedReferences;
    namedReferences =
      builtins.filter
      (entry: entry.reference.name != null)
      configuredReferences;
    namedCredentials = forProducers {
      inherit consumerInstance;
      interface = serviceInterfaces.namedCredential;
      producers =
        builtins.map (entry: {
          key = "${entry.key}-source";
          parameters = {
            inherit (entry.reference) name scope;
          };
        })
        namedReferences;
    };
    credentialDeliveries = forProducers {
      inherit consumerInstance;
      interface = serviceInterfaces.credentialDelivery;
      producers =
        builtins.map (entry: {
          inherit (entry) key;
          parameters = {
            name = entry.name or entry.key;
            source =
              if entry.reference.resource != null
              then entry.reference.resource
              else {
                _type = "aos-request-output-reference";
                request = "${entry.key}-source";
                output = "resource";
              };
            inherit (entry.reference) encrypted;
          };
        })
        configuredReferences;
    };
  in {
    requirementTemplates = namedCredentials.requirementTemplates // credentialDeliveries.requirementTemplates;
    requests = namedCredentials.requests // credentialDeliveries.requests;
  };
in {
  inherit credentialReferenceConfigured featureRequest featureInterfaces forConfiguration forCredentialReferences forProducer forProducers forService instanceOf normalizeCredentialReference splitDefinition structuredSource validate valueFromStructuredSource;
}
