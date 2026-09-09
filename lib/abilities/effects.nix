##! lib/abilities/effects.nix - Pure constructors for finite effect graphs.
##!
##! This initial authoring slice supports omission of whole transition graphs at
##! planning time and the empty transition used by composite fixtures. Operation
##! and runtime-conditional constructors remain unavailable until their Nix
##! normalization can emit the complete Rust decision and merge contracts.
let
  fail = message: throw "ability effects: ${message}";

  isLocalKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;

  profile = {
    max_depth = 64;
    max_nodes = 100000;
    max_edges = 1000000;
    max_collection_items = 2000000;
  };

  requireGraph = context: value:
    if
      builtins.isAttrs value
      && builtins.attrNames value == ["_type" "operations"]
      && value._type == "aos-effect-graph"
      && builtins.isAttrs value.operations
    then value
    else fail "${context} requires a closed effect graph constructed by lib.effects";

  graph = operations:
    if !builtins.isAttrs operations
    then fail "graph requires an attribute set"
    else if operations != {}
    then fail "operation graphs are not available in this authoring slice"
    else {
      _type = "aos-effect-graph";
      inherit operations;
    };

  empty = graph {};

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
    operations = (requireGraph "normalize" effectGraph).operations;
  in
    assert builtins.deepSeq checkedScope true;
      if operations != {}
      then fail "operation graphs are not available in this authoring slice"
      else {
        artifacts = [];
        operations = [];
        decisions = [];
        merges = [];
        edges = [];
      };
in {
  inherit profile graph empty when normalize;
}
