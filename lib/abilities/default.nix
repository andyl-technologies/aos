##! lib/abilities/default.nix - Ability declarations and pure composition.
##!
##! The library creates typed authoring values, validates concrete requests,
##! and expands selected providers without performing effects. Authentication,
##! provider selection, and runtime admission remain native responsibilities.
{
  types,
  mkOption,
}: let
  schemas = import ./schema.nix;
  effects = import ./effects.nix;

  fail = message: throw "abilities: ${message}";

  requireAttrs = context: allowed: value: let
    unexpected =
      if builtins.isAttrs value
      then builtins.filter (name: !(builtins.elem name allowed)) (builtins.attrNames value)
      else [];
  in
    if !builtins.isAttrs value
    then fail "${context} must be an attribute set"
    else if unexpected != []
    then fail "${context} has unsupported fields: ${builtins.concatStringsSep ", " unexpected}"
    else value;

  isLocalKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;

  isAsciiString = value:
    builtins.isString value
    && builtins.match "[[:cntrl:][:print:]]*" value != null;

  requireLocalKey = context: value:
    if isLocalKey value
    then value
    else fail "${context} must match [A-Za-z0-9._-]+ and contain at most 128 bytes";

  requireQualifiedName = context: value:
    if
      builtins.isString value
      && builtins.stringLength value <= 128
      && builtins.match "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+" value != null
    then value
    else fail "${context} must be a namespace-qualified name";

  requireDigest = context: value:
    if builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null
    then value
    else fail "${context} must be a sha256 digest";

  requireU32Positive = context: value:
    if builtins.isInt value && value > 0 && value <= 4294967295
    then value
    else fail "${context} must be a positive 32-bit integer";

  requireChoice = context: choices: value:
    if builtins.elem value choices
    then value
    else fail "${context} is unsupported";

  requireMarker = context: marker: value:
    if builtins.isAttrs value && (value._type or null) == marker
    then value
    else fail "${context} must be constructed by lib.abilities";

  hasAdjacentDuplicate = values:
    (builtins.foldl' (
        state: value: {
          previous = value;
          hasPrevious = true;
          duplicate = state.duplicate || (state.hasPrevious && state.previous == value);
        }
      ) {
        previous = null;
        hasPrevious = false;
        duplicate = false;
      }
      values)
    .duplicate;

  uniqueSortedStrings = context: values: let
    sorted =
      if builtins.isList values && builtins.all builtins.isString values
      then builtins.sort builtins.lessThan values
      else fail "${context} must be a list of strings";
  in
    if hasAdjacentDuplicate sorted
    then fail "${context} contains a duplicate value"
    else sorted;

  qualifiedSortedStrings = context: values:
    builtins.map (requireQualifiedName context) (uniqueSortedStrings context values);

  localSortedStrings = context: values:
    builtins.map (requireLocalKey context) (uniqueSortedStrings context values);

  interfaceKey = args: let
    checked = requireAttrs "interface key" ["name" "abi" "descriptor"] args;
  in {
    name = requireQualifiedName "interface name" checked.name;
    abi = requireU32Positive "interface ABI" checked.abi;
    descriptor = requireDigest "interface descriptor" checked.descriptor;
  };

  guaranteeKey = context: value: let
    checked = requireAttrs context ["name" "version" "descriptor"] value;
  in {
    name = requireQualifiedName "${context} name" checked.name;
    version = requireU32Positive "${context} version" checked.version;
    descriptor = requireDigest "${context} descriptor" checked.descriptor;
  };

  guaranteeLessThan = left: right:
    if left.name != right.name
    then left.name < right.name
    else if left.version != right.version
    then left.version < right.version
    else left.descriptor < right.descriptor;

  canonicalGuarantees = context: values: let
    checked =
      if builtins.isList values
      then builtins.map (guaranteeKey context) values
      else fail "${context} must be a list";
    sorted = builtins.sort guaranteeLessThan checked;
  in
    if hasAdjacentDuplicate sorted
    then fail "${context} contains a duplicate guarantee"
    else sorted;

  normalizeEnvironmentId = value: let
    checked = requireMarker "environment identity" "aos-environment-id" value;
  in
    builtins.removeAttrs checked ["_type"];

  normalizeInstanceId = value: let
    checked = requireMarker "instance identity" "aos-instance-id" value;
  in {
    environment = normalizeEnvironmentId checked.environment;
    inherit (checked) key;
  };

  normalizeRequestId = value: let
    checked = requireMarker "request identity" "aos-request-id" value;
  in {
    consumer = normalizeInstanceId checked.consumer;
    inherit (checked) scope key;
  };

  normalizeBindingReference = value: let
    checked = requireMarker "binding reference" "aos-ability-binding-reference" value;
  in
    builtins.removeAttrs checked ["_type"];

  normalizeArtifactReference = value: let
    checked = requireMarker "artifact reference" "aos-artifact-reference" value;
  in
    builtins.removeAttrs checked ["_type"];

  sameInterface = left: right:
    left.name
    == right.name
    && left.abi == right.abi
    && left.descriptor == right.descriptor;

  normalizeRequirement = alias: value: let
    checked =
      requireAttrs "requirement '${alias}'" [
        "interface"
        "abi"
        "descriptor"
        "methods"
        "guarantees"
        "strength"
        "fallback"
      ]
      value;
  in {
    alias = requireLocalKey "requirement alias" alias;
    accepted_interfaces = [
      (interfaceKey {
        name = checked.interface;
        inherit (checked) abi descriptor;
      })
    ];
    methods = uniqueSortedStrings "requirement '${alias}' methods" checked.methods;
    guarantees = canonicalGuarantees "requirement '${alias}' guarantees" (checked.guarantees or []);
    strength =
      if builtins.elem checked.strength ["required" "advisory"]
      then checked.strength
      else fail "requirement '${alias}' strength is unsupported";
    fallback =
      if (checked.fallback or null) == null
      then null
      else schemas.validateSchema "requirement '${alias}' fallback" checked.fallback;
  };

  normalizeAggregation = value: let
    checked = requireAttrs "aggregation" ["scope" "key" "rejectSlotCollisions" "mergeContract" "controllerGroup"] value;
  in {
    scope =
      if checked.scope == "provider-instance"
      then checked.scope
      else fail "aggregation scope must be 'provider-instance'";
    key = requireLocalKey "aggregation key" checked.key;
    reject_slot_collisions = checked.rejectSlotCollisions;
    merge_contract =
      if (checked.mergeContract or null) == null
      then null
      else requireDigest "aggregation mergeContract" checked.mergeContract;
    controller_group = requireLocalKey "aggregation controllerGroup" checked.controllerGroup;
  };

  normalizeOutput = context: value: let
    checked = requireAttrs context ["schema" "phase" "visibility" "lifetime"] value;
  in {
    schema = schemas.validateSchema "${context} schema" checked.schema;
    inherit (checked) phase visibility lifetime;
  };

  normalizeOutcome = context: value: let
    checked = requireAttrs context ["completionEvidence" "supportsRejectedBeforeEffect" "indeterminate"] value;
  in {
    completion_evidence = schemas.validateSchema "${context} completionEvidence" checked.completionEvidence;
    supports_rejected_before_effect = checked.supportsRejectedBeforeEffect;
    inherit (checked) indeterminate;
  };

  normalizeLifecycle = value: let
    checked =
      requireAttrs "lifecycle" [
        "stableResourceIdentity"
        "releasesEphemeralOnDisable"
        "retainsPersistentByDefault"
        "persistentDeleteMethod"
      ]
      value;
  in {
    stable_resource_identity = checked.stableResourceIdentity;
    releases_ephemeral_on_disable = checked.releasesEphemeralOnDisable;
    retains_persistent_by_default = checked.retainsPersistentByDefault;
    persistent_delete_method =
      if (checked.persistentDeleteMethod or null) == null
      then null
      else requireLocalKey "persistent delete method" checked.persistentDeleteMethod;
  };

  normalizeMethod = name: value: let
    checked =
      requireAttrs "method '${name}'" [
        "operationFamily"
        "parameters"
        "targetResource"
        "outputs"
        "permittedOperations"
        "guarantees"
        "outcome"
      ]
      value;
  in {
    operation_family = checked.operationFamily;
    parameters = schemas.validateSchema "method '${name}' parameters" checked.parameters;
    target_resource = requireQualifiedName "method '${name}' targetResource" checked.targetResource;
    outputs =
      builtins.mapAttrs (
        output: normalizeOutput "method '${name}' output '${requireLocalKey "output name" output}'"
      )
      checked.outputs;
    permitted_operations = uniqueSortedStrings "method '${name}' permittedOperations" checked.permittedOperations;
    guarantees = canonicalGuarantees "method '${name}' guarantees" (checked.guarantees or []);
    outcome = normalizeOutcome "method '${name}' outcome" checked.outcome;
  };

  define = value: let
    checked =
      requireAttrs "export" [
        "interface"
        "abi"
        "requestSchema"
        "outputs"
        "methods"
        "lifecycle"
        "guarantees"
        "aggregation"
        "requires"
        "composeEntry"
        "transitionEntry"
        "ownsResourceKinds"
        "compose"
        "transition"
        "handler"
        "provide"
      ]
      value;
    handler = checked.handler or null;
    compose = checked.compose or null;
    transition = checked.transition or null;
    provide = checked.provide or null;
  in
    if (handler == null) == (compose == null)
    then fail "export must declare exactly one of compose or handler"
    else if compose != null && !builtins.isFunction compose
    then fail "export compose must be a function"
    else if compose != null && !builtins.isFunction transition
    then fail "composite export transition must be a function"
    else if handler != null && transition != null
    then fail "terminal export cannot declare a transition constructor"
    else if provide != null && !builtins.isFunction provide
    then fail "terminal provide must be a function"
    else if compose != null && provide != null
    then fail "composite export cannot declare terminal provide semantics"
    else if handler != null && checked.outputs != {} && provide == null
    then fail "terminal export with desired outputs must declare pure provide semantics"
    else if handler != null && !isLocalKey handler
    then fail "export handler must be a local key"
    else {
      _type = "aos-ability-export";
      interface = {
        name = checked.interface;
        abi = requireU32Positive "interface ABI" checked.abi;
      };
      request_schema = schemas.validateSchema "export requestSchema" checked.requestSchema;
      outputs =
        builtins.mapAttrs (
          name: normalizeOutput "interface output '${requireLocalKey "output name" name}'"
        )
        checked.outputs;
      methods = builtins.mapAttrs normalizeMethod (checked.methods or {});
      lifecycle = normalizeLifecycle checked.lifecycle;
      guarantees = canonicalGuarantees "export guarantees" (checked.guarantees or []);
      aggregation = normalizeAggregation checked.aggregation;
      requirements = builtins.mapAttrs normalizeRequirement (checked.requires or {});
      compose_entry =
        if compose == null
        then null
        else requireLocalKey "composeEntry" checked.composeEntry;
      transition_entry =
        if transition == null
        then null
        else requireLocalKey "transitionEntry" checked.transitionEntry;
      owns_resource_kinds =
        builtins.map
        (requireQualifiedName "owned resource kind")
        (uniqueSortedStrings "owned resource kinds" (checked.ownsResourceKinds or []));
      inherit compose transition handler provide;
    };

  normalizeExport = value: let
    export = requireMarker "export" "aos-ability-export" value;
  in {
    inherit (export.interface) name abi;
    request = export.request_schema;
    inherit (export) outputs methods lifecycle guarantees;
  };

  normalizeImplementation = artifact: value: let
    export = requireMarker "export" "aos-ability-export" value;
  in {
    interface =
      if export.interface ? descriptor
      then export.interface
      else fail "provider implementation requires a validator-derived interface descriptor pin";
    artifact = normalizeArtifactReference artifact;
    requirements =
      builtins.map
      (alias: export.requirements.${alias})
      (builtins.attrNames export.requirements);
    implementation =
      if export.handler != null
      then {
        kind = "terminal-handler";
        handler = export.handler;
      }
      else {
        kind = "pure-composition";
        compose_entry = export.compose_entry;
        transition_entry = export.transition_entry;
      };
    owns_resource_kinds = export.owns_resource_kinds;
  };

  normalizeExportDeclaration = name: implementation: value: let
    export = requireMarker "export" "aos-ability-export" value;
  in {
    name = requireLocalKey "package export name" name;
    interface =
      if export.interface ? descriptor
      then export.interface
      else fail "package export requires a validator-derived interface descriptor pin";
    aggregation = export.aggregation;
    implementation = requireDigest "provider implementation descriptor" implementation;
  };

  normalizeContribution = export: value: let
    contribution = requireMarker "contribution" "aos-ability-contribution" value;
  in {
    request = normalizeRequestId contribution.request;
    inherit (contribution) slot grant;
    value = checkCompositionValue export.request_schema contribution.value;
  };

  stageRank = stage:
    {
      build = 0;
      initrd = 1;
      host = 2;
      system-container = 3;
      user = 4;
      application-container = 5;
    }.${
      stage
    };

  scopeLessThan = left: right:
    if left == []
    then right != []
    else if right == []
    then false
    else if builtins.head left != builtins.head right
    then builtins.head left < builtins.head right
    else scopeLessThan (builtins.tail left) (builtins.tail right);

  requestIdLessThan = left: right: let
    leftEnvironment = left.consumer.environment;
    rightEnvironment = right.consumer.environment;
  in
    if leftEnvironment.authority != rightEnvironment.authority
    then leftEnvironment.authority < rightEnvironment.authority
    else if leftEnvironment.key != rightEnvironment.key
    then leftEnvironment.key < rightEnvironment.key
    else if leftEnvironment.stage != rightEnvironment.stage
    then stageRank leftEnvironment.stage < stageRank rightEnvironment.stage
    else if left.consumer.key != right.consumer.key
    then left.consumer.key < right.consumer.key
    else if left.scope != right.scope
    then scopeLessThan left.scope right.scope
    else left.key < right.key;

  contributionLessThan = left: right:
    if left.slot != right.slot
    then left.slot < right.slot
    else requestIdLessThan left.request right.request;

  canonicalContributions = export: values: let
    checked =
      if builtins.isList values && builtins.length values <= 2000000
      then builtins.map (normalizeContribution export) values
      else fail "contributions must fit the bounded profile";
    sorted = builtins.sort contributionLessThan checked;
    duplicateSlot =
      (
        builtins.foldl' (
          state: entry:
            if state.duplicate != null
            then state
            else {
              previous = entry.slot;
              duplicate =
                if state.previous == entry.slot
                then entry.slot
                else null;
            }
        ) {
          previous = null;
          duplicate = null;
        }
        sorted
      ).duplicate;
  in
    if export.aggregation.reject_slot_collisions && duplicateSlot != null
    then fail "exclusive contribution slot collision: ${duplicateSlot}"
    else sorted;

  validateBindings = export: bindings: let
    requirementAliases = builtins.attrNames export.requirements;
    bindingAliases = builtins.attrNames bindings;
    unexpected = builtins.filter (name: !(builtins.elem name requirementAliases)) bindingAliases;
    checked =
      builtins.mapAttrs (
        alias: value: let
          binding = requireMarker "binding '${alias}'" "aos-ability-binding-reference" value;
        in
          if binding.requirement != alias
          then fail "binding '${alias}' names requirement '${binding.requirement}'"
          else if
            !builtins.any
            (candidate: sameInterface binding.interface candidate)
            export.requirements.${alias}.accepted_interfaces
          then fail "binding '${alias}' does not match its declared interface"
          else binding
      )
      bindings;
  in
    if unexpected != []
    then fail "undeclared requirement bindings: ${builtins.concatStringsSep ", " unexpected}"
    else checked;

  containsRequestOutput = depth: value:
    if depth > 64
    then fail "composition value exceeds 64 structural levels"
    else if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
    then true
    else if builtins.isAttrs value && !((value.type or null) == "derivation")
    then builtins.any (containsRequestOutput (depth + 1)) (builtins.attrValues value)
    else if builtins.isList value
    then builtins.any (containsRequestOutput (depth + 1)) value
    else false;

  checkCompositionValue = schemaValue: value: let
    schema = schemas.validateSchema "composition value schema" schemaValue;
    marker = builtins.isAttrs value && (value._type or null) == "aos-request-output-reference";
    invalid = expected: fail "composition value must be ${expected}";
  in
    if marker
    then value
    else if !containsRequestOutput 0 value
    then schemas.checkValue schema value
    else if schema.kind == "list"
    then
      if builtins.isList value && builtins.length value <= schema.max_items
      then builtins.map (checkCompositionValue schema.element) value
      else invalid "a bounded list"
    else if schema.kind == "map"
    then let
      entries =
        if builtins.isAttrs value
        then value
        else invalid "a map";
      names = builtins.attrNames entries;
      validKey = name:
        isAsciiString name
        && builtins.stringLength name <= schema.key.max_length
        && (
          schema.key.syntax
          == null
          || (schema.key.syntax == "local-key-v1" && isLocalKey name)
          || (
            schema.key.syntax
            == "qualified-name-v1"
            && builtins.match "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+" name != null
            && builtins.stringLength name <= 128
          )
        );
    in
      if builtins.length names > schema.max_entries || !(builtins.all validKey names)
      then invalid "a map with valid bounded keys"
      else builtins.mapAttrs (_: checkCompositionValue schema.value) entries
    else if schema.kind == "record"
    then let
      record =
        if builtins.isAttrs value
        then value
        else invalid "a record";
      names = builtins.attrNames record;
      fieldNames = builtins.attrNames schema.fields;
      missing =
        builtins.filter (
          name: !(builtins.elem name schema.optional_fields) && !(builtins.hasAttr name record)
        )
        fieldNames;
      unexpected = builtins.filter (name: !(builtins.hasAttr name schema.fields)) names;
    in
      if missing != [] || unexpected != []
      then invalid "a closed record with all required fields"
      else builtins.mapAttrs (name: checkCompositionValue schema.fields.${name}) record
    else if schema.kind == "tagged-union"
    then let
      tag =
        if builtins.isAttrs value
        then value.${schema.tag} or null
        else null;
    in
      if builtins.isString tag && builtins.hasAttr tag schema.variants
      then checkCompositionValue schema.variants.${tag} value
      else invalid "a declared tagged-union variant"
    else if schema.kind == "optional"
    then
      if value == null
      then null
      else checkCompositionValue schema.value value
    else invalid "a literal value without a nested symbolic projection";

  compose = args: let
    checkedArgs = requireAttrs "compose arguments" ["export" "contributions" "bindings" "instance" "scope"] args;
    export = requireMarker "export" "aos-ability-export" checkedArgs.export;
    instance = requireMarker "instance context" "aos-instance-context" checkedArgs.instance;
    scope = builtins.map (requireLocalKey "composition scope") (checkedArgs.scope or []);
    contributions = canonicalContributions export checkedArgs.contributions;
    bindings = validateBindings export checkedArgs.bindings;
    requests = builtins.listToAttrs (builtins.map (entry: {
        name = entry.slot;
        value = entry.value;
      })
      contributions);
    authored =
      if export.handler != null
      then
        if export.provide == null
        then {
          requests = {};
          outputs = {};
          resources = [];
          conditionalRequirements = [];
        }
        else
          export.provide {
            inherit requests;
            instance = instance.values // {id = instance.id;};
          }
      else
        export.compose {
          inherit requests bindings;
          instance = instance.values // {id = instance.id;};
        };
    checkedAuthored =
      requireAttrs "composition result" [
        "requests"
        "outputs"
        "resources"
        "conditionalRequirements"
      ]
      authored;
    childRequests =
      builtins.mapAttrs (
        name: child: let
          checked = requireAttrs "child request '${name}'" ["through" "parameters" "lifetime" "slot"] child;
          binding = requireMarker "child request '${name}' binding" "aos-ability-binding-reference" checked.through;
          alias = binding.requirement;
          selected = bindings.${alias} or null;
          requirement = export.requirements.${alias};
          requestIdentity = {
            _type = "aos-request-id";
            consumer = instance.id;
            scope = scope ++ [name];
            key = name;
          };
        in {
          key =
            if
              selected
              != null
              && selected.binding == binding.binding
              && selected.provider_key == binding.provider_key
              && sameInterface selected.interface binding.interface
            then requireLocalKey "child request key" name
            else fail "child request '${name}' does not use its declared binding";
          through = binding;
          request = requestIdentity;
          id = normalizeRequestId requestIdentity;
          inherit (requirement) accepted_interfaces methods guarantees;
          lifetime =
            if builtins.elem (checked.lifetime or "instance") ["attempt" "transaction" "instance" "persistent"]
            then checked.lifetime or "instance"
            else fail "child request '${name}' has unsupported lifetime";
          slot = requireLocalKey "child request '${name}' slot" (checked.slot or "${instance.id.key}.${name}");
          value = checked.parameters;
        }
      )
      checkedAuthored.requests;
    terminalRequests = export.handler != null && checkedAuthored.requests != {};

    outputNames = builtins.attrNames export.outputs;
    missingOutputs = builtins.filter (name: !(builtins.hasAttr name checkedAuthored.outputs)) outputNames;
    unexpectedOutputs = builtins.filter (name: !(builtins.hasAttr name export.outputs)) (builtins.attrNames checkedAuthored.outputs);
    outputs =
      builtins.mapAttrs (
        name: value: checkCompositionValue export.outputs.${name}.schema value
      )
      checkedAuthored.outputs;
    activeRequirements =
      uniqueSortedStrings
      "conditional requirements"
      (checkedAuthored.conditionalRequirements or []);
    unknownActiveRequirements =
      builtins.filter
      (alias: !(builtins.hasAttr alias export.requirements))
      activeRequirements;
    unboundActiveRequirements =
      builtins.filter
      (alias: !(builtins.hasAttr alias bindings))
      activeRequirements;
  in
    {
      provider = normalizeInstanceId instance.id;
      interface = export.interface;
      aggregate = {
        provider = normalizeInstanceId instance.id;
        group = export.aggregation.controller_group;
      };
      inherit scope contributions outputs;
      child_requests = builtins.map (name: childRequests.${name}) (builtins.attrNames childRequests);
      resources = checkedAuthored.resources or [];
      conditional_requirements = activeRequirements;
      terminal_handler = export.handler;
    }
    // (
      if missingOutputs != []
      then fail "composition omits outputs: ${builtins.concatStringsSep ", " missingOutputs}"
      else if unexpectedOutputs != []
      then fail "composition returned undeclared outputs: ${builtins.concatStringsSep ", " unexpectedOutputs}"
      else if unknownActiveRequirements != []
      then fail "composition activated undeclared requirements: ${builtins.concatStringsSep ", " unknownActiveRequirements}"
      else if unboundActiveRequirements != []
      then fail "composition activated unbound requirements: ${builtins.concatStringsSep ", " unboundActiveRequirements}"
      else if terminalRequests
      then fail "terminal provide semantics cannot emit lower requests"
      else {}
    );

  appendPending = providerName: contribution: pending:
    pending
    // {
      ${providerName} = [contribution] ++ (pending.${providerName} or []);
    };

  countPending = pending:
    builtins.foldl'
    (count: contributions: count + builtins.length contributions)
    0
    (builtins.attrValues pending);

  expand = args: let
    checkedArgs = requireAttrs "expansion arguments" ["roots" "providers"] args;
    providers =
      if builtins.isAttrs checkedArgs.providers
      then checkedArgs.providers
      else fail "providers must be an attribute set";
    roots =
      if builtins.isList checkedArgs.roots && builtins.length checkedArgs.roots <= 100000
      then checkedArgs.roots
      else fail "roots must fit the bounded profile";

    validateProvider = providerName: let
      provider =
        if builtins.hasAttr providerName providers
        then providers.${providerName}
        else fail "selected provider '${providerName}' is absent";
      checked = requireAttrs "provider '${providerName}'" ["export" "instance" "bindings" "scope"] provider;
      scope =
        builtins.map
        (requireLocalKey "provider '${providerName}' scope")
        (checked.scope or [providerName]);
    in
      if builtins.length scope > 63
      then fail "provider '${providerName}' scope leaves no room for a child request"
      else checked // {inherit scope;};

    registryValid = let
      state = builtins.foldl' (
        accumulated: providerName: let
          provider = validateProvider providerName;
          export = requireMarker "provider export" "aos-ability-export" provider.export;
          aggregate = builtins.toJSON {
            provider = normalizeInstanceId provider.instance.id;
            group = export.aggregation.controller_group;
          };
        in
          if builtins.hasAttr aggregate accumulated
          then fail "provider aliases '${accumulated.${aggregate}}' and '${providerName}' name the same aggregate"
          else accumulated // {${aggregate} = providerName;}
      ) {} (builtins.attrNames providers);
    in
      builtins.length (builtins.attrNames state) == builtins.length (builtins.attrNames providers);

    rootPending =
      builtins.foldl' (
        pending: root: let
          checked = requireAttrs "expansion root" ["provider" "contributions"] root;
          providerName = requireLocalKey "root provider" checked.provider;
          contributions =
            if builtins.isList checked.contributions
            then checked.contributions
            else fail "root contributions must be a list";
        in
          builtins.foldl'
          (state: contribution: appendPending providerName contribution state)
          (pending // {${providerName} = pending.${providerName} or [];})
          contributions
      ) {}
      roots;

    composeRound = pending:
      builtins.mapAttrs (
        providerName: contributions: let
          provider = validateProvider providerName;
        in
          compose {
            export = provider.export;
            inherit contributions;
            bindings = provider.bindings or {};
            instance = provider.instance;
            inherit (provider) scope;
          }
      )
      pending;

    resolveComposition = nodes: sourceName: schemaValue: value: trail: let
      schema = schemas.validateSchema "composition projection schema" schemaValue;
      marker = builtins.isAttrs value && (value._type or null) == "aos-request-output-reference";
      sourceNode = nodes.${sourceName};
    in
      if marker
      then let
        matches =
          builtins.filter
          (child: child.key == value.request)
          sourceNode.child_requests;
        child =
          if builtins.length matches == 1
          then builtins.head matches
          else fail "resultOf names unknown child request '${value.request}' in '${sourceName}'";
        targetName = child.through.provider_key;
        referenceName = "${sourceName}.${value.request}.${value.output}";
      in
        if builtins.elem referenceName trail
        then fail "composition output cycle includes '${referenceName}'"
        else if !(builtins.hasAttr targetName nodes)
        then value
        else let
          targetExport = (validateProvider targetName).export;
        in
          if !(builtins.hasAttr value.output targetExport.outputs)
          then fail "resultOf references absent output '${targetName}.${value.output}'"
          else if !(builtins.hasAttr value.output nodes.${targetName}.outputs)
          then fail "provider '${targetName}' omitted output '${value.output}'"
          else let
            descriptor = targetExport.outputs.${value.output};
            targetValue = nodes.${targetName}.outputs.${value.output};
          in
            if !(builtins.elem descriptor.phase ["evaluation" "planning"])
            then fail "resultOf '${referenceName}' is unavailable during pure composition"
            else if descriptor.schema != schema
            then fail "resultOf '${referenceName}' has a different output schema"
            else resolveComposition nodes targetName schema targetValue (trail ++ [referenceName])
      else let
        checked = checkCompositionValue schema value;
      in
        if !containsRequestOutput 0 checked
        then checked
        else if schema.kind == "list"
        then builtins.map (entry: resolveComposition nodes sourceName schema.element entry trail) checked
        else if schema.kind == "map"
        then builtins.mapAttrs (_: entry: resolveComposition nodes sourceName schema.value entry trail) checked
        else if schema.kind == "record"
        then
          builtins.mapAttrs
          (name: entry: resolveComposition nodes sourceName schema.fields.${name} entry trail)
          checked
        else if schema.kind == "tagged-union"
        then let
          variant = schema.variants.${checked.${schema.tag}};
        in
          builtins.mapAttrs
          (name: entry: resolveComposition nodes sourceName variant.fields.${name} entry trail)
          checked
        else if schema.kind == "optional"
        then
          if checked == null
          then null
          else resolveComposition nodes sourceName schema.value checked trail
        else fail "symbolic composition output occurs under a scalar schema";

    emitNodeRequests = nodes: sourceName: pending: node:
      builtins.foldl' (
        state: child: let
          targetName = child.through.provider_key;
          target = validateProvider targetName;
          targetExport = requireMarker "target export" "aos-ability-export" target.export;
          childValue =
            if sameInterface child.through.interface targetExport.interface
            then resolveComposition nodes sourceName targetExport.request_schema child.value []
            else fail "selected provider '${targetName}' implements a different interface";
          contribution = {
            _type = "aos-ability-contribution";
            inherit (child) request slot;
            grant = child.through.binding;
            value = childValue;
            _source = sourceName;
          };
        in
          appendPending targetName contribution state
      )
      pending
      node.child_requests;

    nextPending = nodes:
      builtins.foldl'
      (pending: sourceName: emitNodeRequests nodes sourceName pending nodes.${sourceName})
      rootPending
      (builtins.attrNames nodes);

    validateNodeGraph = nodes: let
      names = builtins.attrNames nodes;
      targets = name:
        builtins.map
        (child: child.through.provider_key)
        nodes.${name}.child_requests;
      visit = path: resolved: name:
        if builtins.hasAttr name resolved
        then resolved
        else if builtins.elem name path
        then fail "recursive provider cycle: ${builtins.concatStringsSep " -> " (path ++ [name])}"
        else let
          knownTargets =
            builtins.filter
            (target: builtins.hasAttr target nodes)
            (targets name);
          withTargets =
            builtins.foldl'
            (state: target: visit (path ++ [name]) state target)
            resolved
            knownTargets;
        in
          withTargets // {${name} = true;};
      resolved = builtins.foldl' (visit []) {} names;
    in
      builtins.length (builtins.attrNames resolved) == builtins.length names;

    converge = round: pending:
      if round > 64
      then fail "composition did not converge within 64 rounds"
      else if builtins.length (builtins.attrNames pending) > 100000
      then fail "composition exceeds 100000 provider aggregates"
      else if countPending pending > 2000000
      then fail "composition exceeds 2000000 contributions"
      else let
        nodes = composeRound pending;
        following = nextPending nodes;
      in
        assert validateNodeGraph nodes;
          if following == pending
          then {inherit round nodes;}
          else converge (round + 1) following;

    result = converge 1 rootPending;
  in
    assert registryValid;
    assert validateNodeGraph result.nodes; {
      _type = "aos-ability-expansion";
      inherit (result) round;
      nodes =
        builtins.map
        (providerName: result.nodes.${providerName} // {registry_key = providerName;})
        (builtins.attrNames result.nodes);
    };

  transition = args: let
    checked =
      requireAttrs "transition arguments" [
        "export"
        "scope"
        "old"
        "desired"
        "changes"
        "resources"
        "bindings"
        "observations"
      ]
      args;
    export = requireMarker "export" "aos-ability-export" checked.export;
  in
    if export.transition == null
    then fail "export does not define a transition constructor"
    else
      effects.normalize checked.scope (export.transition {
        inherit (checked) old desired changes resources bindings observations;
      });
in rec {
  inherit
    schemas
    effects
    define
    normalizeExport
    normalizeExportDeclaration
    normalizeImplementation
    compose
    expand
    transition
    ;

  guarantee = value:
    guaranteeKey "guarantee" value;

  resultOf = request: output: {
    _type = "aos-request-output-reference";
    request = requireLocalKey "result request" request;
    output = requireLocalKey "result output" output;
  };

  pinInterface = args: let
    checked = requireAttrs "interface pin" ["export" "descriptor"] args;
    export = requireMarker "interface pin export" "aos-ability-export" checked.export;
  in
    export
    // {
      interface =
        export.interface
        // {
          descriptor = requireDigest "interface pin descriptor" checked.descriptor;
        };
    };

  environmentId = args: let
    checked = requireAttrs "environment identity" ["authority" "key" "stage"] args;
  in {
    _type = "aos-environment-id";
    authority = requireLocalKey "environment authority" checked.authority;
    key = requireLocalKey "environment key" checked.key;
    stage =
      requireChoice "environment stage" [
        "build"
        "initrd"
        "host"
        "system-container"
        "user"
        "application-container"
      ]
      checked.stage;
  };

  instanceId = args: let
    checked = requireAttrs "instance identity" ["environment" "key"] args;
  in {
    _type = "aos-instance-id";
    environment = requireMarker "instance environment" "aos-environment-id" checked.environment;
    key = requireLocalKey "instance key" checked.key;
  };

  requestId = args: let
    checked = requireAttrs "request identity" ["consumer" "scope" "key"] args;
    scope = builtins.map (requireLocalKey "request scope") checked.scope;
  in {
    _type = "aos-request-id";
    consumer = requireMarker "request consumer" "aos-instance-id" checked.consumer;
    scope =
      if builtins.length scope <= 64
      then scope
      else fail "request scope exceeds 64 components";
    key = requireLocalKey "request key" checked.key;
  };

  instance = args: let
    checked = requireAttrs "instance context" ["id" "values"] args;
  in {
    _type = "aos-instance-context";
    id = requireMarker "instance id" "aos-instance-id" checked.id;
    values = checked.values;
  };

  request = args: let
    checked = requireAttrs "ability import" ["interface" "abi" "descriptor" "request"] args;
  in {
    _type = "aos-ability-import";
    interface = interfaceKey {
      name = checked.interface;
      inherit (checked) abi descriptor;
    };
    inherit (checked) request;
  };

  bindingReference = args: let
    checked = requireAttrs "binding reference" ["binding" "requirement" "providerKey" "provider" "interface"] args;
  in {
    _type = "aos-ability-binding-reference";
    binding = requireLocalKey "binding key" checked.binding;
    requirement = requireLocalKey "binding requirement" checked.requirement;
    provider_key = requireLocalKey "binding provider key" checked.providerKey;
    provider = normalizeInstanceId checked.provider;
    interface = interfaceKey checked.interface;
  };

  contribution = args: let
    checked = requireAttrs "contribution" ["request" "slot" "grant" "value"] args;
  in {
    _type = "aos-ability-contribution";
    request = requireMarker "contribution request" "aos-request-id" checked.request;
    slot = requireLocalKey "contribution slot" checked.slot;
    grant = requireLocalKey "contribution grant" checked.grant;
    inherit (checked) value;
  };

  resourceReference = args: let
    checked =
      requireAttrs "resource reference" [
        "interface"
        "resource"
        "operations"
        "lifetime"
      ]
      args;
  in {
    _type = "aos-resource-reference";
    interface = interfaceKey checked.interface;
    resource = {
      provider = normalizeInstanceId checked.resource.provider;
      key = requireLocalKey "resource key" checked.resource.key;
    };
    operations = localSortedStrings "resource operations" checked.operations;
    lifetime = requireChoice "resource lifetime" ["attempt" "transaction" "instance" "persistent"] checked.lifetime;
  };

  artifactReference = args: let
    checked = requireAttrs "artifact reference" ["content" "storePath" "narHash" "closure"] args;
  in {
    _type = "aos-artifact-reference";
    content = requireDigest "artifact content" checked.content;
    store_path =
      if builtins.isString checked.storePath
      then checked.storePath
      else fail "artifact storePath must be a string";
    nar_hash = requireDigest "artifact NAR hash" checked.narHash;
    closure = requireDigest "artifact closure" checked.closure;
  };

  interfaceDocument = requiredFeatures: export: {
    schema = "aos.ability.interface/v1";
    required_features = uniqueSortedStrings "required features" requiredFeatures;
    interface = normalizeExport export;
  };

  declarationModule = let
    exportType = types.coercedTo types.attrs define (types.mkOptionType {
      name = "ability export";
      check = value: (value._type or null) == "aos-ability-export";
    });
    importType = types.coercedTo types.attrs request (types.mkOptionType {
      name = "ability import";
      check = value: (value._type or null) == "aos-ability-import";
    });
    bindingType = types.coercedTo types.attrs bindingReference (types.mkOptionType {
      name = "ability binding";
      check = value: (value._type or null) == "aos-ability-binding-reference";
    });
  in {
    options = {
      abilities.exports = mkOption {
        type = types.attrsOf exportType;
        default = {};
        description = "Package-authored ability exports.";
      };
      abilities.imports = mkOption {
        type = types.attrsOf importType;
        default = {};
        description = "Package-authored ability requests.";
      };
      abilityBindings = mkOption {
        type = types.attrsOf bindingType;
        default = {};
        description = "Deployment-owned exact ability bindings.";
      };
    };
  };
}
