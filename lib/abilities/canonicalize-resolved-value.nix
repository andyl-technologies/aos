##! Restores schema-declared collection order after source value resolution.
{semanticJson}: let
  objectSchemaKinds = [
    "map"
    "record"
    "document-record"
    "tagged-union"
    "artifact-reference"
    "resource-reference"
    "provider-assignment"
    "transaction-blob-reference"
  ];

  canonicalize = context: schema: value: let
    descend = nested: canonicalize context nested;
    objectValue =
      builtins.isAttrs value
      && (!(value ? _type) || (schema ? fields && schema.fields ? _type));
  in
    if schema.kind == "list" && builtins.isList value
    then let
      items = builtins.map (descend schema.element) value;
      entries =
        builtins.map (item: {
          encoded = semanticJson item;
          inherit item;
        })
        items;
      ordered =
        if schema.canonical_order or false
        then builtins.sort (left: right: left.encoded < right.encoded) entries
        else entries;
      encodings = builtins.map (entry: entry.encoded) ordered;
      distinct =
        builtins.length encodings
        == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (encoded: {
            name = encoded;
            value = true;
          })
          encodings)));
    in
      if (schema.unique or false) && !distinct
      then throw "${context} has duplicate values after source-stage resolution"
      else builtins.map (entry: entry.item) ordered
    else if schema.kind == "map" && objectValue
    then builtins.mapAttrs (_: descend schema.value) value
    else if builtins.elem schema.kind ["record" "document-record"] && objectValue
    then
      builtins.mapAttrs (name: fieldValue:
        if builtins.hasAttr name schema.fields
        then descend schema.fields.${name} fieldValue
        else fieldValue)
      value
    else if schema.kind == "tagged-union" && objectValue
    then let
      variant = value.${schema.tag} or null;
    in
      if variant != null && builtins.hasAttr variant schema.variants
      then descend schema.variants.${variant} value
      else value
    else if schema.kind == "disjoint-union"
    then let
      acceptsShape = candidate:
        if candidate.kind == "refined" || candidate.kind == "optional"
        then acceptsShape candidate.value
        else if candidate.kind == "list"
        then builtins.isList value
        else if builtins.elem candidate.kind objectSchemaKinds
        then objectValue
        else if candidate.kind == "boolean"
        then builtins.isBool value
        else if candidate.kind == "integer"
        then builtins.isInt value
        else builtins.isString value;
      selected = builtins.filter acceptsShape schema.variants;
    in
      if builtins.length selected == 1
      then descend (builtins.head selected) value
      else value
    else if schema.kind == "optional" && value != null
    then descend schema.value value
    else if schema.kind == "refined"
    then descend schema.value value
    else value;
in
  canonicalize
