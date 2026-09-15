##! Expands one manager-neutral service declaration into feature requests.
{serviceInterfaces}: let
  featureInterfaces = {
    lifecycle = serviceInterfaces.lifecycle;
    dependencies = serviceInterfaces.dependencies;
    conditions = serviceInterfaces.conditions;
    instantiation = serviceInterfaces.instantiation;
    supervision = serviceInterfaces.supervision;
    readiness = serviceInterfaces.readiness;
    reload = serviceInterfaces.reload;
    termination = serviceInterfaces.termination;
    watchdog = serviceInterfaces.watchdog;
    start_policy = serviceInterfaces.startPolicy;
    failure_policy = serviceInterfaces.failurePolicy;
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
    identity = serviceInterfaces.identity;
    isolation = serviceInterfaces.isolation;
    linux_isolation = serviceInterfaces.linuxIsolation;
  };

  uniqueBy = field: values:
    builtins.length values
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value.${field};
        value = true;
      })
      values)));

  validate = serviceTypes: declaration: let
    lifecycle = declaration.lifecycle;
    startCommandCount = builtins.length lifecycle.start;
    reload = declaration.reload or null;
    instantiation = declaration.instantiation or null;
    supervision = declaration.supervision or null;
    startPolicy = declaration.start_policy or null;
    resources = declaration.resources or null;
    environment = declaration.environment or null;
    directories = declaration.directories or null;
    activation = declaration.activation or null;
    readiness = declaration.readiness or null;
    identity = declaration.identity or null;
    credentials = declaration.credentials or null;
    configuration = declaration.configuration or null;
    storage = declaration.storage or null;
    socketActivation = declaration.socket_activation or null;
    logging = declaration.logging or null;
    linuxIsolation = declaration.linux_isolation or null;
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
        then (instantiation.template or null) == null && (instantiation.instance or null) == null
        else if instantiation.kind == "template"
        then (instantiation.template or null) != null && (instantiation.instance or null) == null
        else (instantiation.template or null) != null && (instantiation.instance or null) != null
      );
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
    finiteResourceValue = quantity:
      if quantity.kind == "finite"
      then quantity.value
      else null;
    memoryRangeValid =
      resources
      == null
      || (let
        high = finiteResourceValue resources.memory_high_bytes;
        maximum = finiteResourceValue resources.memory_max_bytes;
      in
        high == null || maximum == null || high <= maximum);
    directoriesValid =
      directories
      == null
      || builtins.length directories.managed
      == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (directory: {
          name = "${directory.purpose}:${directory.name}";
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
      || uniqueBy "name" activation.bindings;
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
      || uniqueBy "name" socketActivation.sockets;
    loggingValid =
      logging
      == null
      || builtins.length logging.directories
      == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
          inherit name;
          value = true;
        })
        logging.directories)));
    linuxIsolationValid =
      linuxIsolation
      == null
      || (
        builtins.length linuxIsolation.namespace_isolation
        == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
            inherit name;
            value = true;
          })
          linuxIsolation.namespace_isolation)))
        && builtins.length linuxIsolation.network_address_families
        == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
            inherit name;
            value = true;
          })
          linuxIsolation.network_address_families)))
      );
    capabilityBoundsValid =
      linuxIsolation
      == null
      || builtins.all
      (capability: builtins.elem capability linuxIsolation.bounding_capabilities)
      linuxIsolation.ambient_capabilities;
    syscallSetsDisjoint =
      linuxIsolation
      == null
      || builtins.all
      (syscall: !(builtins.elem syscall linuxIsolation.syscall_deny))
      linuxIsolation.syscall_allow;
  in
    if !serviceTypes.serviceDeclaration.check declaration
    then throw "service declaration does not match the canonical service type"
    else if startCommandCount == 0
    then throw "service '${declaration.service}' must declare at least one start command"
    else if lifecycle.execution_model != "oneshot" && startCommandCount != 1
    then throw "service '${declaration.service}' must declare exactly one start command unless it is oneshot"
    else if !reloadValid
    then throw "service '${declaration.service}' reload strategy has inconsistent commands or signal"
    else if !instantiationValid
    then throw "service '${declaration.service}' instantiation kind has inconsistent template or instance fields"
    else if !supervisionValid
    then throw "service '${declaration.service}' supervision protocol has inconsistent notification access or bus name"
    else if !startPolicyValid
    then throw "service '${declaration.service}' start rate interval and burst must be declared together"
    else if !memoryRangeValid
    then throw "service '${declaration.service}' finite memory high limit must not exceed its maximum"
    else if !directoriesValid
    then throw "service '${declaration.service}' has duplicate managed directory names"
    else if !environmentValid
    then throw "service '${declaration.service}' environment.variables cannot define PATH when search_path is non-empty"
    else if !activationValid
    then throw "service '${declaration.service}' has duplicate activation binding names"
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
    then throw "service '${declaration.service}' has duplicate socket names"
    else if !loggingValid
    then throw "service '${declaration.service}' has duplicate log directory names"
    else if !linuxIsolationValid
    then throw "service '${declaration.service}' Linux isolation lists must not contain duplicate namespace or address-family entries"
    else if !capabilityBoundsValid
    then throw "service '${declaration.service}' ambient capabilities must be included in its bounding capability set"
    else if !syscallSetsDisjoint
    then throw "service '${declaration.service}' syscall allow and deny sets must be disjoint"
    else declaration;

  requirementFor = interface: methods: {
    description = interface.declaration.description;
    inherit (interface.identity) abi descriptor;
    interface = interface.identity.name;
    inherit methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };

  namespaceOf = consumerInstance: let
    matched = builtins.match "([^:]+):[^:]+" consumerInstance;
  in
    if matched == null
    then null
    else builtins.head matched;
  qualify = namespace: name:
    if namespace == null || builtins.match "[^:]+:[^:]+" name != null
    then name
    else "${namespace}:${name}";
  qualifyResults = namespace: value:
    if namespace == null
    then value
    else if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then value // {request = qualify namespace value.request;}
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: qualifyResults namespace) value
    else if builtins.isList value
    then builtins.map (qualifyResults namespace) value
    else value;
  qualifyForConsumer = consumerInstance: contribution: let
    namespace = namespaceOf consumerInstance;
  in
    if namespace == null
    then contribution
    else {
      requirementTemplates = builtins.listToAttrs (builtins.map (name: {
          name = qualify namespace name;
          value = contribution.requirementTemplates.${name};
        })
        (builtins.attrNames contribution.requirementTemplates));
      requests = builtins.listToAttrs (builtins.map (name: {
          name = qualify namespace name;
          value = let
            request = contribution.requests.${name};
          in
            request
            // {
              requirement = qualify namespace request.requirement;
              parameters = qualifyResults namespace request.parameters;
            };
        })
        (builtins.attrNames contribution.requests));
    };

  requestParameters = declaration: feature: let
    featureValue = declaration.${feature};
  in
    {
      inherit (declaration) service enabled;
    }
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
    unwrapOptional = schema:
      if schema.kind == "optional"
      then schema.value
      else schema;
    scalarKind = schema: let
      concrete = unwrapOptional schema;
    in
      if concrete.kind == "boolean"
      then "boolean"
      else if concrete.kind == "integer"
      then "integer"
      else if builtins.elem concrete.kind ["string" "string-enum"]
      then "string"
      else throw "deferred structured configuration leaves must have Boolean, integer, or string schemas";
    nodesAt = path: schema: current: let
      concrete = unwrapOptional schema;
    in
      if current == null && schema.kind == "optional"
      then [
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
          kind = "string";
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
      else if concrete.kind == "record"
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

  forService = {
    serviceTypes,
    consumerInstance,
    declaration,
  }: let
    checked = validate serviceTypes declaration;
    enabledFeatures =
      builtins.filter
      (feature: feature == "lifecycle" || checked.${feature} or null != null)
      (builtins.attrNames featureInterfaces);
    methodsFor = feature:
      if feature == "lifecycle" && (checked.reload or null) == null
      then builtins.filter (method: method != "reload") featureInterfaces.lifecycle.methods
      else featureInterfaces.${feature}.methods;
    contribution = {
      requirementTemplates = builtins.listToAttrs (builtins.map (feature: {
          name = featureInterfaces.${feature}.alias;
          value = requirementFor featureInterfaces.${feature} (methodsFor feature);
        })
        enabledFeatures);
      requests = builtins.listToAttrs (builtins.map (feature: {
          name = "${checked.service}-${feature}";
          value = {
            requirement = featureInterfaces.${feature}.alias;
            consumer = consumerInstance;
            scope = [checked.service];
            parameters = requestParameters checked feature;
          };
        })
        enabledFeatures);
    };
  in
    qualifyForConsumer consumerInstance contribution;

  forConfiguration = {
    serviceTypes,
    consumerInstance,
    declaration,
  }: let
    source = declaration.source or {};
    structuredValid =
      (source.kind or null)
      != "structured-value"
      || serviceTypes.structuredDocumentValid source;
    checked =
      if !serviceTypes.configurationMaterialization.check declaration
      then throw "managed configuration does not match the canonical materialization type"
      else if !structuredValid
      then throw "managed configuration '${declaration.name}' has an invalid structured document tree"
      else declaration;
    interface = serviceInterfaces.managedConfiguration;
    contribution = {
      requirementTemplates.${interface.alias} = requirementFor interface interface.methods;
      requests.${checked.name} = {
        requirement = interface.alias;
        consumer = consumerInstance;
        scope = [checked.name];
        parameters = checked;
      };
    };
  in
    qualifyForConsumer consumerInstance contribution;

  forProducers = {
    consumerInstance,
    interface,
    producers,
  }: let
    contribution =
      if !uniqueBy "key" producers
      then throw "producer request keys must be unique"
      else {
        requirementTemplates =
          if producers == []
          then {}
          else {${interface.alias} = requirementFor interface interface.methods;};
        requests = builtins.listToAttrs (builtins.map (producer: {
            name = producer.key;
            value = {
              requirement = interface.alias;
              consumer = consumerInstance;
              scope = [producer.key];
              inherit (producer) parameters;
            };
          })
          producers);
      };
  in
    qualifyForConsumer consumerInstance contribution;

  forProducer = args:
    forProducers {
      inherit (args) consumerInstance interface;
      producers = [
        {
          inherit (args) key parameters;
        }
      ];
    };
in {
  inherit featureInterfaces forConfiguration forProducer forProducers forService structuredSource validate;
}
