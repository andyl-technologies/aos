##! lib/abilities/effects/default.nix - Pure finite effect-plan authoring.
##!
##! Provider transition constructors build operation DAGs with planning-time
##! omission and finite runtime selection. Normalization assigns recursive
##! scopes, records branch membership, emits explicit decision/merge edges,
##! retains every referenced artifact, and rejects incomplete or cyclic graphs.
let
  schemas = import ../schema.nix;

  fail = message: throw "ability effects: ${message}";

  profile = {
    max_document_bytes = 32 * 1024 * 1024;
    max_depth = 64;
    max_nodes = 100000;
    max_edges = 1000000;
    max_collection_items = 2000000;
    max_string_bytes = 1048576;
  };

  maxSafeInteger = 9007199254740991;
  maxStringLength = 1048576;
  maxAnalysisSteps = 5 * profile.max_nodes;

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

  requireLocalKey = context: value:
    if isLocalKey value
    then value
    else fail "${context} must be a version-1 local key";

  requireChoice = context: choices: value:
    if builtins.elem value choices
    then value
    else fail "${context} is unsupported";

  requireDigest = context: value:
    if builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null
    then value
    else fail "${context} must be a sha256 digest";

  requirePositive = context: value:
    if builtins.isInt value && value > 0 && value <= maxSafeInteger
    then value
    else fail "${context} must be a positive canonical integer";

  requireNonNegative = context: value:
    if builtins.isInt value && value >= 0 && value <= maxSafeInteger
    then value
    else fail "${context} must be a non-negative canonical integer";

  requireU32Positive = context: value:
    if builtins.isInt value && value > 0 && value <= 4294967295
    then value
    else fail "${context} must be a positive 32-bit integer";

  isAsciiString = value:
    builtins.isString value
    && builtins.match "[[:cntrl:][:print:]]*" value != null;

  uniqueSortedLocalKeys = context: values: let
    checked =
      if builtins.isList values && builtins.length values <= profile.max_collection_items
      then builtins.map (requireLocalKey context) values
      else fail "${context} must be a bounded list";
    sorted = builtins.sort builtins.lessThan checked;
    state =
      builtins.foldl' (
        accumulated: value: {
          previous = value;
          duplicate = accumulated.duplicate || (accumulated.previous != null && accumulated.previous == value);
        }
      ) {
        previous = null;
        duplicate = false;
      }
      sorted;
  in
    if state.duplicate
    then fail "${context} contains a duplicate"
    else sorted;

  normalizeInterfaceKey = context: value: let
    checked = requireAttrs context ["name" "abi" "descriptor"] value;
  in {
    name =
      if
        builtins.isString checked.name
        && builtins.stringLength checked.name <= 128
        && builtins.match "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+" checked.name != null
      then checked.name
      else fail "${context} name must be namespace-qualified";
    abi = requireU32Positive "${context} ABI" checked.abi;
    descriptor = requireDigest "${context} descriptor" checked.descriptor;
  };

  executionStages = [
    "build"
    "initrd"
    "host"
    "system-container"
    "user"
    "application-container"
  ];

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

  normalizeEnvironmentId = context: value: let
    checked = requireAttrs context ["authority" "key" "stage"] value;
  in {
    authority = requireLocalKey "${context} authority" checked.authority;
    key = requireLocalKey "${context} key" checked.key;
    stage = requireChoice "${context} stage" executionStages checked.stage;
  };

  normalizeInstanceId = context: value: let
    checked = requireAttrs context ["environment" "key"] value;
  in {
    environment = normalizeEnvironmentId "${context} environment" checked.environment;
    key = requireLocalKey "${context} key" checked.key;
  };

  normalizeResourceId = context: value: let
    checked = requireAttrs context ["provider" "key"] value;
  in {
    provider = normalizeInstanceId "${context} provider" checked.provider;
    key = requireLocalKey "${context} key" checked.key;
  };

  normalizeResourceReference = context: value: let
    checked = requireAttrs context ["_type" "interface" "resource" "operations" "lifetime"] value;
  in
    if checked._type != "aos-resource-reference"
    then fail "${context} must be constructed by lib.abilities.resourceReference"
    else {
      interface = normalizeInterfaceKey "${context} interface" checked.interface;
      resource = normalizeResourceId "${context} resource" checked.resource;
      operations = uniqueSortedLocalKeys "${context} operations" checked.operations;
      lifetime = requireChoice "${context} lifetime" ["attempt" "transaction" "instance" "persistent"] checked.lifetime;
    };

  normalizeArtifactReference = context: value: let
    checked = requireAttrs context ["_type" "content" "store_path" "nar_hash" "closure"] value;
  in
    if checked._type != "aos-artifact-reference"
    then fail "${context} must be constructed by lib.abilities.artifactReference"
    else {
      content = requireDigest "${context} content" checked.content;
      store_path =
        if builtins.isString checked.store_path
        then checked.store_path
        else fail "${context} store path must be a string";
      nar_hash = requireDigest "${context} NAR hash" checked.nar_hash;
      closure = requireDigest "${context} closure" checked.closure;
    };

  normalizeBindingReference = context: value: let
    checked =
      requireAttrs context [
        "_type"
        "binding"
        "requirement"
        "provider_key"
        "provider"
        "interface"
      ]
      value;
  in
    if checked._type != "aos-ability-binding-reference"
    then fail "${context} must be constructed by lib.abilities.bindingReference"
    else {
      binding = requireLocalKey "${context} binding" checked.binding;
      requirement = requireLocalKey "${context} requirement" checked.requirement;
      provider_key = requireLocalKey "${context} provider key" checked.provider_key;
      provider = normalizeInstanceId "${context} provider" checked.provider;
      interface = normalizeInterfaceKey "${context} interface" checked.interface;
    };

  scopeLessThan = left: right:
    if left == []
    then right != []
    else if right == []
    then false
    else if builtins.head left != builtins.head right
    then builtins.head left < builtins.head right
    else scopeLessThan (builtins.tail left) (builtins.tail right);

  scopedKeyLessThan = left: right:
    if left.scope != right.scope
    then scopeLessThan left.scope right.scope
    else left.key < right.key;

  scopedKey = scope: key: {
    inherit scope;
    key = requireLocalKey "effect node key" key;
  };

  nodeRank = kind:
    {
      operation = 0;
      decision = 1;
      merge = 2;
    }.${
      kind
    };

  planNode = kind: key: {
    inherit kind key;
  };

  nodeLessThan = left: right:
    if left.key != right.key
    then scopedKeyLessThan left.key right.key
    else nodeRank left.kind < nodeRank right.kind;

  nodeIdentity = node: builtins.toJSON node;

  edgeRank = kind:
    {
      data = 0;
      required-success = 1;
      ordering-only = 2;
      readiness = 3;
      branch-guard = 4;
      branch-merge = 5;
      retention = 6;
      communication = 7;
    }.${
      kind
    };

  edgeLessThan = left: right:
    if left.from != right.from
    then nodeLessThan left.from right.from
    else if left.to != right.to
    then nodeLessThan left.to right.to
    else edgeRank left.kind < edgeRank right.kind;

  reverseList = values:
    builtins.foldl' (reversed: value: [value] ++ reversed) [] values;

  take = count: values:
    builtins.genList (index: builtins.elemAt values index) count;

  scopeIsPrefix = prefix: scope:
    builtins.length prefix
    <= builtins.length scope
    && take (builtins.length prefix) scope == prefix;

  deduplicateSorted = values: let
    state =
      builtins.foldl' (
        accumulated: value:
          if accumulated.previous != null && accumulated.previous == value
          then accumulated
          else {
            previous = value;
            reversed = [value] ++ accumulated.reversed;
          }
      ) {
        previous = null;
        reversed = [];
      }
      values;
  in
    reverseList state.reversed;

  canonicalArtifacts = values: let
    sorted =
      builtins.sort (
        left: right:
          if left.content != right.content
          then left.content < right.content
          else builtins.toJSON left < builtins.toJSON right
      )
      values;
    state =
      builtins.foldl' (
        accumulated: value:
          if accumulated.previous == null || accumulated.previous.content != value.content
          then {
            previous = value;
            reversed = [value] ++ accumulated.reversed;
          }
          else if accumulated.previous == value
          then accumulated
          else fail "artifact content '${value.content}' has conflicting reference metadata"
      ) {
        previous = null;
        reversed = [];
      }
      sorted;
  in
    reverseList state.reversed;

  readinessLessThan = left: right:
    if left.binding != right.binding
    then left.binding < right.binding
    else if left.producer != right.producer
    then scopedKeyLessThan left.producer right.producer
    else left.output < right.output;

  canonicalProviderReadiness = values: let
    sorted = builtins.sort readinessLessThan values;
    state =
      builtins.foldl' (
        accumulated: value:
          if accumulated.previous != null && accumulated.previous.binding == value.binding
          then fail "binding '${value.binding}' has more than one provider-readiness declaration"
          else {
            previous = value;
            reversed = [value] ++ accumulated.reversed;
          }
      ) {
        previous = null;
        reversed = [];
      }
      sorted;
  in
    reverseList state.reversed;

  normalizeOperationFamily = value: let
    kind =
      if builtins.isAttrs value && builtins.isString (value.kind or null)
      then value.kind
      else fail "operation family must contain a string kind";
    simple = [
      "verify-artifact"
      "prepare-managed-configuration"
      "validate-candidate"
      "publish-configuration"
      "prepare-manager-configuration"
      "observe-readiness"
      "release-resource"
      "record-generation-association"
    ];
  in
    if builtins.elem kind simple
    then requireAttrs "operation family '${kind}'" ["kind"] value
    else if kind == "credential"
    then let
      checked = requireAttrs "credential operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "credential action" ["acquire" "deliver"] checked.action;}
    else if kind == "service-lifecycle"
    then let
      checked = requireAttrs "service lifecycle operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "service lifecycle action" ["start" "reload" "restart" "stop"] checked.action;}
    else fail "operation family '${kind}' is unsupported";

  normalizeAggregateId = context: value: let
    checked = requireAttrs context ["provider" "group"] value;
  in {
    provider = normalizeInstanceId "${context} provider" checked.provider;
    group = requireLocalKey "${context} group" checked.group;
  };

  normalizePrecondition = value: let
    checked = requireAttrs "operation precondition" ["resource" "expected_revision" "expected_incarnation"] value;
    optionalDigest = context: candidate:
      if candidate == null
      then null
      else requireDigest context candidate;
  in {
    resource = normalizeResourceId "precondition resource" checked.resource;
    expected_revision = optionalDigest "precondition expected revision" checked.expected_revision;
    expected_incarnation =
      if checked.expected_incarnation == null
      then null
      else if
        builtins.isString checked.expected_incarnation
        && builtins.stringLength checked.expected_incarnation > 0
        && builtins.stringLength checked.expected_incarnation <= 1024
      then checked.expected_incarnation
      else fail "precondition expected incarnation must be a bounded non-empty string";
  };

  normalizeAccess = value: let
    checked = requireAttrs "operation access" ["resource" "mode"] value;
  in {
    resource = normalizeResourceId "access resource" checked.resource;
    mode = requireChoice "access mode" ["read" "shared-write" "exclusive-write"] checked.mode;
  };

  resourceLessThan = left: right: let
    leftProvider = left.provider;
    rightProvider = right.provider;
    leftEnvironment = leftProvider.environment;
    rightEnvironment = rightProvider.environment;
  in
    if leftEnvironment.authority != rightEnvironment.authority
    then leftEnvironment.authority < rightEnvironment.authority
    else if leftEnvironment.key != rightEnvironment.key
    then leftEnvironment.key < rightEnvironment.key
    else if leftEnvironment.stage != rightEnvironment.stage
    then stageRank leftEnvironment.stage < stageRank rightEnvironment.stage
    else if leftProvider.key != rightProvider.key
    then leftProvider.key < rightProvider.key
    else left.key < right.key;

  canonicalByResource = context: normalizeValue: values: let
    checked =
      if builtins.isList values && builtins.length values <= profile.max_collection_items
      then builtins.map normalizeValue values
      else fail "${context} must be a bounded list";
    sorted = builtins.sort (left: right: resourceLessThan left.resource right.resource) checked;
    state =
      builtins.foldl' (
        accumulated: value: {
          previous = value.resource;
          duplicate = accumulated.duplicate || (accumulated.previous != null && accumulated.previous == value.resource);
        }
      ) {
        previous = null;
        duplicate = false;
      }
      sorted;
  in
    if state.duplicate
    then fail "${context} names one resource more than once"
    else sorted;

  normalizeMethodReference = context: value:
    if value == null
    then null
    else let
      checked = requireAttrs context ["interface" "method"] value;
    in {
      interface = normalizeInterfaceKey "${context} interface" checked.interface;
      method = requireLocalKey "${context} method" checked.method;
    };

  normalizeRecovery = value: let
    checked = requireAttrs "recovery contract" ["retry" "reconcile" "cancel" "compensate"] value;
    retryKind =
      if builtins.isAttrs checked.retry && builtins.isString (checked.retry.kind or null)
      then checked.retry.kind
      else fail "retry policy must contain a string kind";
    retry =
      if retryKind == "disabled"
      then requireAttrs "disabled retry policy" ["kind"] checked.retry
      else if retryKind == "bounded"
      then let
        bounded = requireAttrs "bounded retry policy" ["kind" "max_attempts" "backoff_millis"] checked.retry;
      in
        bounded
        // {
          max_attempts = requireU32Positive "retry max attempts" bounded.max_attempts;
          backoff_millis = requireNonNegative "retry backoff" bounded.backoff_millis;
        }
      else fail "retry policy '${retryKind}' is unsupported";
  in {
    inherit retry;
    reconcile = normalizeMethodReference "recovery reconcile method" checked.reconcile;
    cancel = normalizeMethodReference "recovery cancel method" checked.cancel;
    compensate = normalizeMethodReference "recovery compensate method" checked.compensate;
  };

  normalizeDeadline = value: let
    checked = requireAttrs "deadline policy" ["attempt_timeout_millis" "total_recovery_millis"] value;
  in {
    attempt_timeout_millis = requirePositive "attempt timeout" checked.attempt_timeout_millis;
    total_recovery_millis = requirePositive "total recovery timeout" checked.total_recovery_millis;
  };

  normalizeOutputDescriptor = context: value: let
    checked = requireAttrs context ["schema" "phase" "visibility" "lifetime"] value;
  in {
    schema = schemas.validateSchema "${context} schema" checked.schema;
    phase = requireChoice "${context} phase" ["evaluation" "artifact" "planning" "admission" "runtime" "observation"] checked.phase;
    visibility = requireChoice "${context} visibility" ["public" "protected" "private"] checked.visibility;
    lifetime = requireChoice "${context} lifetime" ["attempt" "transaction" "instance" "persistent"] checked.lifetime;
  };

  requireCanonicalLiteral = depth: value:
    if depth > profile.max_depth
    then fail "literal input exceeds ${builtins.toString profile.max_depth} structural levels"
    else if builtins.isBool value || value == null
    then value
    else if builtins.isInt value && value >= -maxSafeInteger && value <= maxSafeInteger
    then value
    else if
      builtins.isString value
      && builtins.stringLength value <= maxStringLength
    then value
    else if builtins.isList value && builtins.length value <= profile.max_collection_items
    then builtins.map (requireCanonicalLiteral (depth + 1)) value
    else if builtins.isAttrs value && builtins.length (builtins.attrNames value) <= profile.max_collection_items
    then
      if builtins.all isAsciiString (builtins.attrNames value)
      then builtins.mapAttrs (_: requireCanonicalLiteral (depth + 1)) value
      else fail "literal input contains a non-ASCII object member name"
    else fail "literal input is outside the canonical ability value domain";

  isTypedReference = value:
    builtins.isAttrs value
    && builtins.elem (value._type or null) [
      "aos-artifact-reference"
      "aos-resource-reference"
      "aos-effect-result-reference"
    ];

  containsTypedReference = depth: value:
    if depth > profile.max_depth
    then fail "effect input exceeds ${builtins.toString profile.max_depth} structural levels"
    else if isTypedReference value
    then true
    else if builtins.isList value
    then
      if builtins.length value <= profile.max_collection_items
      then builtins.any (containsTypedReference (depth + 1)) value
      else fail "effect input collection exceeds the bounded profile"
    else if builtins.isAttrs value
    then
      if
        builtins.length (builtins.attrNames value)
        <= profile.max_collection_items
        && builtins.all
        (name: isAsciiString name && builtins.stringLength name <= maxStringLength)
        (builtins.attrNames value)
      then builtins.any (containsTypedReference (depth + 1)) (builtins.attrValues value)
      else fail "effect input object exceeds the bounded canonical key profile"
    else false;

  collectionItemCount = depth: value:
    if depth > profile.max_depth
    then fail "effect input exceeds ${builtins.toString profile.max_depth} structural levels"
    else if isTypedReference value
    then 0
    else if builtins.isList value
    then let
      count =
        builtins.length value
        + builtins.foldl'
        (total: nested: total + collectionItemCount (depth + 1) nested)
        0
        value;
    in
      if count <= profile.max_collection_items
      then count
      else fail "effect input exceeds ${builtins.toString profile.max_collection_items} collection items"
    else if builtins.isAttrs value
    then let
      names = builtins.attrNames value;
      count =
        builtins.length names
        + builtins.foldl'
        (total: nested: total + collectionItemCount (depth + 1) nested)
        0
        (builtins.attrValues value);
    in
      if
        count
        <= profile.max_collection_items
        && builtins.all
        (name: isAsciiString name && builtins.stringLength name <= maxStringLength)
        names
      then count
      else fail "effect input exceeds the bounded canonical object profile"
    else 0;

  boundedAdd = limit: left: right:
    if left > limit || right > limit || left > limit - right
    then limit + 1
    else left + right;

  canonicalDocumentStats = depth: value:
    if depth > profile.max_depth
    then fail "normalized effect plan exceeds ${builtins.toString profile.max_depth} structural levels"
    else if value == null || builtins.isBool value
    then {
      items = 0;
      bytes = builtins.stringLength (builtins.toJSON value);
    }
    else if builtins.isInt value && value >= -maxSafeInteger && value <= maxSafeInteger
    then {
      items = 0;
      bytes = builtins.stringLength (builtins.toJSON value);
    }
    else if builtins.isString value && builtins.stringLength value <= profile.max_string_bytes
    then {
      items = 0;
      bytes = builtins.stringLength (builtins.toJSON value);
    }
    else if builtins.isList value
    then let
      length = builtins.length value;
      initial = {
        items = length;
        bytes =
          if length == 0
          then 2
          else length + 1;
      };
      stats =
        builtins.foldl' (
          state: childValue:
            if state.items > profile.max_collection_items || state.bytes > profile.max_document_bytes
            then state
            else let
              child = canonicalDocumentStats (depth + 1) childValue;
            in {
              items = boundedAdd profile.max_collection_items state.items child.items;
              bytes = boundedAdd profile.max_document_bytes state.bytes child.bytes;
            }
        )
        initial
        value;
    in
      if stats.items <= profile.max_collection_items
      then stats
      else fail "normalized effect plan exceeds the collection item limit"
    else if builtins.isAttrs value
    then let
      names = builtins.attrNames value;
      validNames =
        builtins.all (
          name: isAsciiString name && builtins.stringLength name <= profile.max_string_bytes
        )
        names;
      length = builtins.length names;
      initial = {
        items = length;
        bytes =
          if length == 0
          then 2
          else length + 1;
      };
      stats =
        builtins.foldl' (
          state: name:
            if state.items > profile.max_collection_items || state.bytes > profile.max_document_bytes
            then state
            else let
              child = canonicalDocumentStats (depth + 1) value.${name};
              keyBytes = builtins.stringLength (builtins.toJSON name) + 1;
            in {
              items = boundedAdd profile.max_collection_items state.items child.items;
              bytes = boundedAdd profile.max_document_bytes state.bytes (keyBytes + child.bytes);
            }
        )
        initial
        names;
    in
      if !validNames
      then fail "normalized effect plan contains a non-canonical object member name"
      else if stats.items > profile.max_collection_items
      then fail "normalized effect plan exceeds the collection item limit"
      else stats
    else fail "normalized effect plan is outside the canonical JSON value domain";

  resultReference = kind: up: key: output: {
    _type = "aos-effect-result-reference";
    inherit kind;
    inherit up;
    key = requireLocalKey "result producer" key;
    output = requireLocalKey "result output" output;
  };

  requireResultReference = context: value: let
    checked = requireAttrs context ["_type" "kind" "up" "key" "output"] value;
  in
    if checked._type != "aos-effect-result-reference"
    then fail "${context} must be constructed by lib.effects.result or lib.effects.mergedResult"
    else {
      kind = requireChoice "${context} producer kind" ["operation" "merge"] checked.kind;
      up =
        if builtins.isInt checked.up && checked.up >= 0 && checked.up <= profile.max_depth
        then checked.up
        else fail "${context} ancestor distance must be between 0 and ${builtins.toString profile.max_depth}";
      key = requireLocalKey "${context} producer key" checked.key;
      output = requireLocalKey "${context} output" checked.output;
    };

  normalizeResultReference = rootDepth: scope: value: let
    reference = requireResultReference "result reference" value;
    scopeLength = builtins.length scope;
    producerScope =
      if reference.up <= scopeLength - rootDepth
      then take (scopeLength - reference.up) scope
      else fail "result reference escapes the effect graph root";
  in {
    producer = {
      inherit (reference) kind;
      key = scopedKey producerScope reference.key;
    };
    inherit (reference) output;
  };

  producerNode = reference: planNode reference.producer.kind reference.producer.key;

  normalizeProviderReadiness = rootDepth: scope: value: let
    checked = requireAttrs "provider-readiness declaration" ["binding" "producer"] value;
    binding = normalizeBindingReference "provider-readiness binding" checked.binding;
    producer = normalizeResultReference rootDepth scope checked.producer;
  in
    if producer.producer.kind != "operation"
    then fail "provider-readiness evidence must be produced by an operation"
    else {
      inherit (binding) binding;
      producer = producer.producer.key;
      inherit (producer) output;
      consumer_scope = scope;
    };

  normalizeExpression = rootDepth: scope: depth: value:
    if depth > profile.max_depth
    then fail "effect input exceeds ${builtins.toString profile.max_depth} structural levels"
    else if builtins.isAttrs value && (value._type or null) == "aos-effect-result-reference"
    then {
      source = "operation-result";
      reference = normalizeResultReference rootDepth scope value;
    }
    else if builtins.isAttrs value && (value._type or null) == "aos-resource-reference"
    then {
      source = "resource-reference";
      reference = normalizeResourceReference "effect input resource" value;
    }
    else if builtins.isAttrs value && (value._type or null) == "aos-artifact-reference"
    then {
      source = "artifact-reference";
      reference = normalizeArtifactReference "effect input artifact" value;
    }
    else if !containsTypedReference depth value
    then {
      source = "literal";
      value = requireCanonicalLiteral depth value;
    }
    else if builtins.isList value
    then {
      source = "list";
      items = builtins.map (normalizeExpression rootDepth scope (depth + 1)) value;
    }
    else if builtins.isAttrs value
    then
      if builtins.all isAsciiString (builtins.attrNames value)
      then {
        source = "object";
        fields = builtins.mapAttrs (_: normalizeExpression rootDepth scope (depth + 1)) value;
      }
      else fail "effect input contains a non-ASCII object member name"
    else fail "unsupported reference-bearing effect input";

  collectResults = depth: value:
    if depth > profile.max_depth
    then fail "effect input exceeds ${builtins.toString profile.max_depth} structural levels"
    else if builtins.isAttrs value && (value._type or null) == "aos-effect-result-reference"
    then [value]
    else if builtins.isList value
    then builtins.concatLists (builtins.map (collectResults (depth + 1)) value)
    else if builtins.isAttrs value
    then builtins.concatLists (builtins.map (collectResults (depth + 1)) (builtins.attrValues value))
    else [];

  collectArtifacts = depth: value:
    if depth > profile.max_depth
    then fail "effect input exceeds ${builtins.toString profile.max_depth} structural levels"
    else if builtins.isAttrs value && (value._type or null) == "aos-artifact-reference"
    then [(normalizeArtifactReference "effect input artifact" value)]
    else if builtins.isList value
    then builtins.concatLists (builtins.map (collectArtifacts (depth + 1)) value)
    else if builtins.isAttrs value
    then builtins.concatLists (builtins.map (collectArtifacts (depth + 1)) (builtins.attrValues value))
    else [];

  nodeReference = kind: key: {
    _type = "aos-effect-node-reference";
    inherit kind;
    key = requireLocalKey "dependency node" key;
  };

  normalizeNodeReference = scope: value: let
    reference =
      if builtins.isString value
      then {
        kind = "operation";
        key = requireLocalKey "dependency operation" value;
      }
      else let
        checked = requireAttrs "dependency reference" ["_type" "kind" "key"] value;
      in
        if checked._type != "aos-effect-node-reference"
        then fail "dependency must name an operation or use a lib.effects node reference"
        else {
          kind = requireChoice "dependency node kind" ["operation" "decision" "merge"] checked.kind;
          key = requireLocalKey "dependency node key" checked.key;
        };
  in
    planNode reference.kind (scopedKey scope reference.key);

  normalizeDependency = scope: value: let
    checked = requireAttrs "effect dependency" ["kind" "node"] value;
  in {
    kind =
      requireChoice "dependency kind" [
        "required-success"
        "ordering-only"
        "readiness"
        "retention"
        "communication"
      ]
      checked.kind;
    node = normalizeNodeReference scope checked.node;
  };

  requireInvocation = value:
    requireAttrs "effect invocation" [
      "_type"
      "target"
      "through"
      "authority"
      "method"
      "family"
      "phase"
      "inputPhase"
      "inputs"
      "preconditions"
      "accesses"
      "controller"
      "deadline"
      "recovery"
      "dependencies"
    ]
    value;

  requireGraph = context: value: let
    checked = requireAttrs context ["_type" "nodes" "providerReadiness"] value;
  in
    if
      checked._type
      != "aos-effect-graph"
      || !builtins.isAttrs checked.nodes
      || !builtins.isList checked.providerReadiness
    then fail "${context} must be a closed graph constructed by lib.effects.graph"
    else checked;

  requireConditional = value:
    requireAttrs "runtime conditional" [
      "_type"
      "mode"
      "selector"
      "tag_field"
      "alternatives"
      "outputs"
    ]
    value;

  guardEdges = branchContext: node:
    builtins.map (membership: {
      from = planNode "decision" membership.decision;
      to = node;
      kind = "branch-guard";
    })
    branchContext;

  normalizeOperation = rootDepth: scope: branchContext: name: authored: let
    invocation = requireInvocation authored;
    through = normalizeBindingReference "operation binding" invocation.through;
    target = normalizeResourceReference "operation target" invocation.target;
    key = scopedKey scope name;
    node = planNode "operation" key;
    inputItemCount = collectionItemCount 0 invocation.inputs;
    inputs = assert inputItemCount <= profile.max_collection_items;
      normalizeExpression rootDepth scope 0 invocation.inputs;
    resultEdges = builtins.map (reference: {
      from = producerNode (normalizeResultReference rootDepth scope reference);
      to = node;
      kind = "data";
    }) (collectResults 0 invocation.inputs);
    dependencyEdges =
      builtins.map (dependency: let
        normalized = normalizeDependency scope dependency;
      in {
        from = normalized.node;
        to = node;
        inherit (normalized) kind;
      })
      invocation.dependencies;
  in
    if target.interface != through.interface
    then fail "operation '${name}' target and binding interfaces differ"
    else {
      artifacts = collectArtifacts 0 invocation.inputs;
      operations = [
        {
          inherit key;
          branch_context = branchContext;
          binding = through.binding;
          authority = requireChoice "operation '${name}' authority" ["caller" "provider"] invocation.authority;
          interface = through.interface;
          method = requireLocalKey "operation '${name}' method" invocation.method;
          family = normalizeOperationFamily invocation.family;
          phase = requireChoice "operation '${name}' phase" ["preparing" "publishing" "converging" "recovering"] invocation.phase;
          input_phase = requireChoice "operation '${name}' input phase" ["evaluation" "artifact" "planning" "admission" "runtime" "observation"] invocation.inputPhase;
          inherit target inputs;
          preconditions = canonicalByResource "operation preconditions" normalizePrecondition invocation.preconditions;
          accesses = canonicalByResource "operation accesses" normalizeAccess invocation.accesses;
          controller =
            if invocation.controller == null
            then null
            else normalizeAggregateId "operation controller" invocation.controller;
          deadline = normalizeDeadline invocation.deadline;
          recovery = normalizeRecovery invocation.recovery;
        }
      ];
      decisions = [];
      merges = [];
      edges = resultEdges ++ dependencyEdges ++ guardEdges branchContext node;
      providerReadiness = [];
    };

  normalizeMergedOutput = rootDepth: scope: mergeName: branchScopes: alternativeNames: name: value: let
    checked = requireAttrs "merged output '${name}'" ["descriptor" "alternatives"] value;
    actualAlternatives = builtins.attrNames checked.alternatives;
    references =
      builtins.mapAttrs (
        alternative: reference:
          normalizeResultReference rootDepth branchScopes.${alternative} reference
      )
      checked.alternatives;
    mergeKey = scopedKey scope mergeName;
    localAlternativeProducer = alternative:
      references.${alternative}.producer.key.scope == branchScopes.${alternative};
  in
    if actualAlternatives != alternativeNames
    then fail "merged output '${name}' must name every conditional alternative"
    else if !(builtins.all localAlternativeProducer alternativeNames)
    then fail "merged output '${name}' alternatives must be produced inside their corresponding branches"
    else {
      value = {
        descriptor = normalizeOutputDescriptor "merged output '${name}' descriptor" checked.descriptor;
        alternatives = references;
      };
      edges =
        builtins.map (alternative: {
          from = producerNode references.${alternative};
          to = planNode "merge" mergeKey;
          kind = "branch-merge";
        })
        alternativeNames;
    };

  emptyFragment = {
    artifacts = [];
    operations = [];
    decisions = [];
    merges = [];
    edges = [];
    providerReadiness = [];
  };

  combineFragments = fragments: {
    artifacts = builtins.concatLists (builtins.map (fragment: fragment.artifacts) fragments);
    operations = builtins.concatLists (builtins.map (fragment: fragment.operations) fragments);
    decisions = builtins.concatLists (builtins.map (fragment: fragment.decisions) fragments);
    merges = builtins.concatLists (builtins.map (fragment: fragment.merges) fragments);
    edges = builtins.concatLists (builtins.map (fragment: fragment.edges) fragments);
    providerReadiness = builtins.concatLists (builtins.map (fragment: fragment.providerReadiness) fragments);
  };

  normalizeConditional = rootDepth: scope: branchContext: name: authored: let
    conditional = requireConditional authored;
    alternativeNames = builtins.attrNames conditional.alternatives;
    decisionKey = scopedKey scope name;
    decisionNode = planNode "decision" decisionKey;
    selector = normalizeResultReference rootDepth scope conditional.selector;
    branchScopes = builtins.listToAttrs (builtins.map (alternative: {
        name = alternative;
        value = scope ++ [name alternative];
      })
      alternativeNames);
    branchFragments = builtins.map (alternative:
      normalizeGraph
      rootDepth
      branchScopes.${alternative}
      (branchContext
        ++ [
          {
            decision = decisionKey;
            inherit alternative;
          }
        ])
      conditional.alternatives.${alternative})
    alternativeNames;
    branches = combineFragments branchFragments;
    alternatives =
      builtins.map (alternative: {
        key = alternative;
        predicate =
          if conditional.mode == "boolean"
          then {
            kind = "boolean";
            value = alternative == "true";
          }
          else {
            kind = "tag";
            value = alternative;
          };
      })
      alternativeNames;
    decision = {
      key = decisionKey;
      branch_context = branchContext;
      selector = {
        result = selector;
        tag_field = conditional.tag_field;
      };
      inherit alternatives;
    };
    decisionEdges =
      [
        {
          from = producerNode selector;
          to = decisionNode;
          kind = "data";
        }
      ]
      ++ guardEdges branchContext decisionNode;
    mergeFragments =
      builtins.mapAttrs
      (normalizeMergedOutput rootDepth scope name branchScopes alternativeNames)
      conditional.outputs;
    mergeOutputNames = builtins.attrNames mergeFragments;
    mergeKey = scopedKey scope name;
    mergeNode = planNode "merge" mergeKey;
    hasMerge = mergeOutputNames != [];
    merge = {
      key = mergeKey;
      decision = decisionKey;
      branch_context = branchContext;
      outputs = builtins.mapAttrs (_: fragment: fragment.value) mergeFragments;
    };
    mergeEdges =
      builtins.concatLists (builtins.map (output: mergeFragments.${output}.edges) mergeOutputNames)
      ++ guardEdges branchContext mergeNode;
  in
    if alternativeNames == []
    then fail "runtime conditional '${name}' must contain alternatives"
    else if conditional.mode == "boolean" && alternativeNames != ["false" "true"]
    then fail "Boolean conditional '${name}' must contain exactly false and true alternatives"
    else if conditional.mode == "tag" && conditional.tag_field == null
    then fail "tagged conditional '${name}' must name its discriminator"
    else {
      artifacts = branches.artifacts;
      operations = branches.operations;
      decisions = [decision] ++ branches.decisions;
      merges =
        (
          if hasMerge
          then [merge]
          else []
        )
        ++ branches.merges;
      edges =
        decisionEdges
        ++ branches.edges
        ++ (
          if hasMerge
          then mergeEdges
          else []
        );
      providerReadiness = branches.providerReadiness;
    };

  normalizeNode = rootDepth: scope: branchContext: name: value:
    if !isLocalKey name
    then fail "effect node key '${name}' is invalid"
    else if builtins.isAttrs value && (value._type or null) == "aos-effect-invocation"
    then normalizeOperation rootDepth scope branchContext name value
    else if builtins.isAttrs value && (value._type or null) == "aos-effect-conditional"
    then normalizeConditional rootDepth scope branchContext name value
    else fail "effect node '${name}' is not an invocation or runtime conditional";

  normalizeGraph = rootDepth: scope: branchContext: value: let
    checked = requireGraph "effect graph" value;
    names = builtins.attrNames checked.nodes;
    nodes = combineFragments (builtins.map (name: normalizeNode rootDepth scope branchContext name checked.nodes.${name}) names);
    providerReadiness = builtins.map (normalizeProviderReadiness rootDepth scope) checked.providerReadiness;
  in
    if builtins.length scope > profile.max_depth
    then fail "effect graph scope exceeds ${builtins.toString profile.max_depth} components"
    else if builtins.length branchContext > profile.max_depth
    then fail "effect branch nesting exceeds ${builtins.toString profile.max_depth} levels"
    else if builtins.length names > profile.max_nodes
    then fail "effect graph exceeds ${builtins.toString profile.max_nodes} local nodes"
    else
      nodes
      // {
        providerReadiness = nodes.providerReadiness ++ providerReadiness;
      };

  allNodes = fragment:
    (builtins.map (operation: planNode "operation" operation.key) fragment.operations)
    ++ (builtins.map (decision: planNode "decision" decision.key) fragment.decisions)
    ++ (builtins.map (merge: planNode "merge" merge.key) fragment.merges);

  validateAcyclic = fragment: let
    nodes = allNodes fragment;
    identities = builtins.map nodeIdentity nodes;
    known = builtins.listToAttrs (builtins.map (identity: {
        name = identity;
        value = true;
      })
      identities);
    hasMissing = builtins.any (edge:
      !(builtins.hasAttr (nodeIdentity edge.from) known)
      || !(builtins.hasAttr (nodeIdentity edge.to) known))
    fragment.edges;
    schedulingKinds = [
      "data"
      "required-success"
      "ordering-only"
      "readiness"
      "branch-guard"
      "branch-merge"
    ];
    schedulingEdges = builtins.filter (edge: builtins.elem edge.kind schedulingKinds) fragment.edges;
    startupWork =
      2
      * builtins.length identities
      + builtins.length fragment.edges
      + 2 * builtins.length schedulingEdges;
    outgoing = builtins.groupBy (edge: nodeIdentity edge.from) schedulingEdges;
    incoming = builtins.groupBy (edge: nodeIdentity edge.to) schedulingEdges;
    adjacency = builtins.mapAttrs (_: edges: builtins.map (edge: nodeIdentity edge.to) edges) outgoing;
    indegrees = builtins.listToAttrs (builtins.map (identity: {
        name = identity;
        value = builtins.length (incoming.${identity} or []);
      })
      identities);
    removeReady = remainingWork: remaining: currentIndegrees:
      if remaining == []
      then true
      else let
        ready = builtins.filter (identity: currentIndegrees.${identity} == 0) remaining;
        nextRemaining = builtins.filter (identity: currentIndegrees.${identity} != 0) remaining;
        releasedTargets = builtins.concatLists (
          builtins.map (identity: adjacency.${identity} or []) ready
        );
        released = builtins.groupBy (identity: identity) releasedTargets;
        nextIndegrees = builtins.listToAttrs (builtins.map (identity: {
            name = identity;
            value = currentIndegrees.${identity} - builtins.length (released.${identity} or []);
          })
          nextRemaining);
        roundWork =
          3
          * builtins.length remaining
          + 2 * builtins.length releasedTargets;
      in
        if ready == []
        then fail "effect graph contains a scheduling cycle"
        else if roundWork > remainingWork
        then fail "effect graph exceeds the bounded acyclicity analysis budget"
        else removeReady (remainingWork - roundWork) nextRemaining nextIndegrees;
  in
    if builtins.length identities != builtins.length (builtins.attrNames known)
    then fail "effect graph contains duplicate node identities"
    else if startupWork > maxAnalysisSteps
    then fail "effect graph exceeds the bounded acyclicity analysis budget"
    else if hasMissing
    then fail "effect graph references a missing node"
    else removeReady (maxAnalysisSteps - startupWork) identities indegrees;

  conditional = mode: args: let
    checked = requireAttrs "runtime conditional" ["selector" "tagField" "alternatives" "outputs"] args;
    tagField = checked.tagField or null;
    alternatives =
      if builtins.isAttrs checked.alternatives
      then builtins.mapAttrs (_: requireGraph "conditional alternative") checked.alternatives
      else fail "conditional alternatives must be an attribute set";
    alternativeNames = builtins.attrNames alternatives;
    outputs =
      if builtins.isAttrs (checked.outputs or {})
      then
        builtins.mapAttrs (name: value: let
          output = requireAttrs "conditional output '${name}'" ["descriptor" "alternatives"] value;
        in
          if builtins.attrNames output.alternatives != alternativeNames
          then fail "conditional output '${name}' must name every alternative"
          else output) (checked.outputs or {})
      else fail "conditional outputs must be an attribute set";
    checkedSelector = requireResultReference "conditional selector" checked.selector;
    value = {
      _type = "aos-effect-conditional";
      inherit mode alternatives outputs;
      selector = checked.selector;
      tag_field =
        if tagField == null
        then null
        else requireLocalKey "conditional tag field" tagField;
    };
  in
    builtins.deepSeq checkedSelector (builtins.deepSeq value value);
in rec {
  graph = nodes: let
    value = {
      _type = "aos-effect-graph";
      inherit nodes;
      providerReadiness = [];
    };
  in
    builtins.deepSeq (requireGraph "graph" value) value;

  empty = graph {};

  withProviderReadiness = args: effectGraph: let
    checked = requireAttrs "withProviderReadiness" ["binding" "producer"] args;
    checkedGraph = requireGraph "withProviderReadiness graph" effectGraph;
    declaration = {
      inherit (checked) binding producer;
    };
  in
    assert builtins.deepSeq (normalizeBindingReference "provider-readiness binding" checked.binding) true;
    assert builtins.deepSeq (requireResultReference "provider-readiness producer" checked.producer) true;
      checkedGraph
      // {
        providerReadiness = checkedGraph.providerReadiness ++ [declaration];
      };

  invoke = args: let
    checked =
      requireAttrs "invoke" [
        "target"
        "through"
        "authority"
        "method"
        "family"
        "phase"
        "inputPhase"
        "inputs"
        "preconditions"
        "accesses"
        "controller"
        "deadline"
        "recovery"
      ]
      args;
    value = {
      _type = "aos-effect-invocation";
      inherit
        (checked)
        target
        through
        authority
        family
        phase
        inputs
        preconditions
        accesses
        controller
        deadline
        recovery
        ;
      method = requireLocalKey "invoke method" checked.method;
      inputPhase = checked.inputPhase;
      dependencies = [];
    };
  in
    builtins.deepSeq value value;

  depends = kind: dependencies: invocation: let
    checked = requireInvocation invocation;
    dependencyKind =
      requireChoice "dependency kind" [
        "required-success"
        "ordering-only"
        "readiness"
        "retention"
        "communication"
      ]
      kind;
    additions =
      if builtins.isList dependencies
      then
        builtins.map (node: {
          kind = dependencyKind;
          inherit node;
        })
        dependencies
      else fail "dependencies must be a list";
  in
    checked // {dependencies = checked.dependencies ++ additions;};

  after = depends "required-success";
  orderAfter = depends "ordering-only";
  readyAfter = depends "readiness";
  retainWith = depends "retention";
  communicateWith = depends "communication";

  operationNode = nodeReference "operation";
  decisionNode = nodeReference "decision";
  mergeNode = nodeReference "merge";

  result = resultReference "operation" 0;
  mergedResult = resultReference "merge" 0;

  ancestorResult = up: resultReference "operation" up;
  ancestorMergedResult = up: resultReference "merge" up;

  ifResult = args:
    conditional "boolean" (args // {tagField = null;});

  matchResult = args:
    conditional "tag" args;

  when = condition: effectGraph: let
    checkedGraph = requireGraph "when" effectGraph;
  in
    if !builtins.isBool condition
    then fail "when condition must be a planning-time Boolean"
    else
      assert builtins.deepSeq checkedGraph true;
        if condition
        then checkedGraph
        else empty;

  normalize = scope: effectGraph: let
    checkedScope =
      if
        builtins.isList scope
        && builtins.all isLocalKey scope
        && builtins.length scope <= profile.max_depth
      then scope
      else fail "normalization scope must be a bounded path of local keys";
    authored = normalizeGraph (builtins.length checkedScope) checkedScope [] effectGraph;
    nodeCount = builtins.length authored.operations + builtins.length authored.decisions + builtins.length authored.merges;
    artifactCount = builtins.length authored.artifacts;
    readinessCount = builtins.length authored.providerReadiness;
    operationIdentities = builtins.listToAttrs (builtins.map (operation: {
        name = builtins.toJSON operation.key;
        value = true;
      })
      authored.operations);
    operationsByBinding = builtins.groupBy (operation: operation.binding) authored.operations;
    readinessConsumers = readiness:
      builtins.filter
      (operation: scopeIsPrefix readiness.consumer_scope operation.key.scope)
      (operationsByBinding.${readiness.binding} or []);
    internalProviderReadiness = builtins.map (readiness:
      if !(builtins.hasAttr (builtins.toJSON readiness.producer) operationIdentities)
      then fail "provider-readiness declaration names a missing producer operation"
      else if readinessConsumers readiness == []
      then fail "provider-readiness declaration names a binding unused in its graph"
      else readiness)
    (canonicalProviderReadiness authored.providerReadiness);
    readinessEdgeCount =
      builtins.foldl'
      (count: readiness: boundedAdd profile.max_edges count (builtins.length (readinessConsumers readiness)))
      0
      internalProviderReadiness;
    edgeCount = boundedAdd profile.max_edges (builtins.length authored.edges) readinessEdgeCount;
  in
    assert builtins.deepSeq checkedScope true;
      if nodeCount > profile.max_nodes
      then fail "effect graph exceeds ${builtins.toString profile.max_nodes} nodes"
      else if builtins.length authored.edges > profile.max_edges
      then fail "effect graph exceeds ${builtins.toString profile.max_edges} edges"
      else if artifactCount > profile.max_collection_items
      then fail "effect graph exceeds the artifact collection limit"
      else if readinessCount > profile.max_collection_items
      then fail "effect graph exceeds the provider-readiness collection limit"
      else if edgeCount > profile.max_edges
      then fail "effect graph exceeds ${builtins.toString profile.max_edges} edges"
      else let
        providerReadiness =
          builtins.map (readiness: {
            inherit (readiness) binding producer output;
          })
          internalProviderReadiness;
        readinessEdges = builtins.concatLists (builtins.map (readiness:
          builtins.map (operation: {
            from = planNode "operation" readiness.producer;
            to = planNode "operation" operation.key;
            kind = "readiness";
          }) (readinessConsumers readiness))
        internalProviderReadiness);
        normalized = {
          artifacts = canonicalArtifacts authored.artifacts;
          operations = builtins.sort (left: right: scopedKeyLessThan left.key right.key) authored.operations;
          decisions = builtins.sort (left: right: scopedKeyLessThan left.key right.key) authored.decisions;
          merges = builtins.sort (left: right: scopedKeyLessThan left.key right.key) authored.merges;
          edges = deduplicateSorted (builtins.sort edgeLessThan (authored.edges ++ readinessEdges));
          provider_readiness = providerReadiness;
        };
        documentStats = canonicalDocumentStats 0 normalized;
      in
        assert builtins.deepSeq documentStats true;
          if documentStats.bytes > profile.max_document_bytes
          then fail "normalized effect plan exceeds the encoded byte limit"
          else assert validateAcyclic normalized; normalized;

  inherit profile;
}
