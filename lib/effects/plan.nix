##! Lowers evaluated handler modules into a finite, bound activation graph.
{
  lib,
  abilities,
}: let
  keyFor = identity: builtins.hashString "sha256" (builtins.toJSON identity);
  fail = identity: message:
    throw "Effect '${builtins.concatStringsSep "." identity}': ${message}";

  lower = depth: inheritedOwner: effect: let
    inherit (effect.contract) identity;
    owner =
      if inheritedOwner == null
      then effect.contract.owner
      else inheritedOwner;
    execution = effect.execution;
    childNames = builtins.attrNames execution.children;
    terminal = execution.program != null;
    children = builtins.attrValues effect.children;
    childNodes = builtins.concatMap (child:
      lower (depth + 1) owner (child
        // {
          after = child.after ++ effect.after ++ references effect.input;
        }))
    children;
    node = {
      id = keyFor identity;
      inherit identity owner;
      input = effect.input;
      inputs = effect.contract.inputs;
      input_type = effect.contract.input_type;
      lifetime = effect.lifetime;
      timeout_ms = effect.timeoutMs;
      after = effect.after;
      results = effect.contract.results;
      handler =
        if terminal
        then {
          kind = "process";
          artifact = builtins.toString (lib.getBin execution.program);
          executable = lib.getExe execution.program;
        }
        else {
          kind = "composition";
          children =
            builtins.map (child: keyFor child.contract.identity)
            (builtins.filter (child: child.enable) children);
          exports = execution.exports;
        };
    };
  in
    if !effect.enable
    then []
    else if depth > 64
    then fail identity "handler expansion exceeds 64 levels (possible recursive handler)."
    else if !effect.contract.handled
    then fail identity "no handler is configured for this enabled operation."
    else if terminal && childNames != []
    then fail identity "a handler cannot be both terminal and composed."
    else if !terminal && childNames == []
    then fail identity "the selected handler supplies neither a program nor child effects."
    else [node] ++ childNodes;

  roots = builtins.concatMap (ability:
    builtins.concatMap (operation: builtins.attrValues operation.effects)
    (builtins.attrValues ability.operations))
  (builtins.attrValues abilities);
  nodes = builtins.concatMap (lower 0 null) roots;
  keys = builtins.map (node: node.id) nodes;
  uniqueKeys = lib.unique keys;
  indexed = builtins.listToAttrs (builtins.map (node: {
      name = node.id;
      value = builtins.removeAttrs node ["id"];
    })
    nodes);

  references = value:
    if builtins.isAttrs value && (value._type or null) == "aos-effect-output"
    then [value]
    else if builtins.isAttrs value
    then builtins.concatMap references (builtins.attrValues value)
    else if builtins.isList value
    then builtins.concatMap references value
    else [];

  checkReference = reference: let
    key = keyFor reference.identity;
    producer = indexed.${key} or null;
    # Attribute lookup requires a context-free name. Keep the original reference
    # intact in the node so authorship checks and artifact projection still see
    # the dependency annotations carried by an option default.
    outputName = builtins.unsafeDiscardStringContext reference.output;
  in
    if !lib.types.effectOutput.check reference
    then throw "Activation graph contains a malformed deferred output."
    else if producer == null
    then fail reference.identity "output refers to an absent or disabled effect."
    else if !(producer.results ? ${outputName})
    then fail reference.identity "operation has no output '${reference.output}'."
    else if producer.results.${outputName} != reference.schema
    then fail reference.identity "output '${reference.output}' has an incompatible schema."
    else key;

  dependencies = builtins.mapAttrs (_: node:
    lib.unique (
      builtins.map checkReference (references node.input ++ node.after)
      ++ lib.optionals (node.handler.kind == "composition") (
        node.handler.children ++ builtins.map checkReference (references node.handler.exports)
      )
    ))
  indexed;

  lifetimeRank = {
    transaction = 0;
    instance = 1;
    persistent = 2;
  };

  checkChildLifetimes = node:
    if node.handler.kind != "composition"
    then true
    else
      builtins.all (key: let
        child = indexed.${key};
      in
        if lifetimeRank.${child.lifetime} >= lifetimeRank.${node.lifetime}
        then true
        else fail node.identity "composed child '${builtins.concatStringsSep "." child.identity}' (${child.lifetime}) does not outlive its parent (${node.lifetime}).")
      node.handler.children;

  checkExports = node:
    if node.handler.kind != "composition"
    then true
    else if builtins.attrNames node.handler.exports != builtins.attrNames node.results
    then fail node.identity "composed handler must export exactly its declared results."
    else
      builtins.all (name: let
        output = node.handler.exports.${name};
      in
        if !lib.types.effectOutput.check output || output.schema != node.results.${name}
        then fail node.identity "export '${name}' does not match the operation's result type."
        else builtins.seq (checkReference output) true)
      (builtins.attrNames node.results);

  # Kahn's algorithm checks cycles without revisiting each dependency path.
  order = completed: pending:
    if pending == {}
    then completed
    else let
      ready = builtins.attrNames (lib.filterAttrs (_: parents:
        builtins.all (parent: !(pending ? ${parent})) parents)
      pending);
    in
      if ready == []
      then throw "Activation graph contains a dependency cycle."
      else order (completed ++ ready) (builtins.removeAttrs pending ready);
  executionOrder = order [] dependencies;
  # Schemas describe available choices; they do not select runtime artifacts.
  # Keep their exact JSON values while retaining contexts on concrete inputs
  # and handler programs. Authoring and reference checks use indexed above.
  schemaMetadata = value:
    builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.toJSON value));
  operationalValue = value:
    if builtins.isAttrs value && (value._type or null) == "aos-effect-output"
    then value // {schema = schemaMetadata value.schema;}
    else if builtins.isAttrs value
    then builtins.mapAttrs (_: operationalValue) value
    else if builtins.isList value
    then builtins.map operationalValue value
    else value;
  serializedNode = node:
    node
    // {
      inputs = schemaMetadata node.inputs;
      input_type = schemaMetadata node.input_type;
      results = schemaMetadata node.results;
      input = operationalValue node.input;
      after = operationalValue node.after;
      handler =
        if node.handler.kind == "composition"
        then node.handler // {exports = operationalValue node.handler.exports;}
        else node.handler;
    };
  checkedNodes = builtins.mapAttrs (key: node:
    builtins.seq (checkExports node && checkChildLifetimes node) (let
      normalized = serializedNode node;
    in
      normalized
      // {
        dependencies = dependencies.${key};
        revision = builtins.hashString "sha256" (builtins.toJSON (builtins.removeAttrs normalized ["inputs"]));
      }))
  indexed;
in
  if builtins.length keys != builtins.length uniqueKeys
  then throw "Activation graph contains duplicate effect identities."
  else {
    schema = "aos.activation.graph";
    nodes = checkedNodes;
    order = executionOrder;
  }
