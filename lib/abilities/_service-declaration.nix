##! Expands one manager-neutral service declaration into feature requests.
{serviceInterfaces}: let
  featureInterfaces = {
    lifecycle = serviceInterfaces.lifecycle;
    dependencies = serviceInterfaces.dependencies;
    readiness = serviceInterfaces.readiness;
    reload = serviceInterfaces.reload;
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
        then reload.commands != []
        else reload.commands == []
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
    identityMaskValid =
      identity
      == null
      || builtins.match "[0-7][0-7][0-7]([0-7])?" identity.file_creation_mask != null;
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
    loggingModeValid =
      logging
      == null
      || builtins.match "[0-7][0-7][0-7]([0-7])?" logging.directory_mode != null;
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
    then throw "service '${declaration.service}' command reload strategy must have commands, and other strategies must not"
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
    else if !identityMaskValid
    then throw "service '${declaration.service}' file creation mask must be three or four octal digits"
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
    else if !loggingModeValid
    then throw "service '${declaration.service}' log directory mode must be three or four octal digits"
    else if !linuxIsolationValid
    then throw "service '${declaration.service}' Linux isolation lists must not contain duplicate namespace or address-family entries"
    else if !capabilityBoundsValid
    then throw "service '${declaration.service}' ambient capabilities must be included in its bounding capability set"
    else if !syscallSetsDisjoint
    then throw "service '${declaration.service}' syscall allow and deny sets must be disjoint"
    else declaration;

  requirementFor = interface: {
    description = interface.declaration.description;
    inherit (interface.identity) abi descriptor;
    interface = interface.identity.name;
    methods = interface.methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };

  requestParameters = declaration: feature: let
    featureValue = declaration.${feature};
  in
    {
      inherit (declaration) service enabled;
    }
    // featureValue;

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
  in {
    requirementTemplates = builtins.listToAttrs (builtins.map (feature: {
        name = featureInterfaces.${feature}.alias;
        value = requirementFor featureInterfaces.${feature};
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

  forConfiguration = {
    serviceTypes,
    consumerInstance,
    declaration,
  }: let
    checked =
      if !serviceTypes.configurationMaterialization.check declaration
      then throw "managed configuration does not match the canonical materialization type"
      else if builtins.match "[0-7][0-7][0-7]([0-7])?" declaration.mode == null
      then throw "managed configuration '${declaration.name}' mode must be three or four octal digits"
      else declaration;
    interface = serviceInterfaces.managedConfiguration;
  in {
    requirementTemplates.${interface.alias} = requirementFor interface;
    requests.${checked.name} = {
      requirement = interface.alias;
      consumer = consumerInstance;
      scope = [checked.name];
      parameters = checked;
    };
  };

  forProducer = {
    consumerInstance,
    key,
    interface,
    parameters,
  }: {
    requirementTemplates.${interface.alias} = requirementFor interface;
    requests.${key} = {
      requirement = interface.alias;
      consumer = consumerInstance;
      scope = [key];
      inherit parameters;
    };
  };
in {
  inherit featureInterfaces forConfiguration forProducer forService validate;
}
