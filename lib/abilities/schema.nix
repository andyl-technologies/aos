##! lib/abilities/schema.nix - Portable ability value schemas.
##!
##! Constructors in this file emit closed, JSON-serializable descriptions.
##! The same vocabulary is decoded by the native ability validator. These
##! helpers also validate concrete Nix values early, before serialization.
let
  diagnostics = import ./diagnostic.nix;
  lifetime = import ./lifetime.nix;

  fail = message:
    diagnostics.throw "value-type-mismatch" "ability schema: ${message}";
  failLimit = message:
    diagnostics.throw "limit-exceeded" "ability schema: ${message}";

  maxSafeInteger = 9007199254740991;
  maxStringLength = 1048576;
  maxCollectionItems = 2000000;
  maxSchemaDepth = 64;
  maxPatternLength = 4096;

  requireAttrs = context: allowed: value: let
    unexpected = builtins.filter (name: !(builtins.elem name allowed)) (builtins.attrNames value);
  in
    if !builtins.isAttrs value
    then fail "${context} must be an attribute set"
    else if unexpected != []
    then fail "${context} has unsupported fields: ${builtins.concatStringsSep ", " unexpected}"
    else value;

  requirePositive = context: value:
    if builtins.isInt value && value > 0
    then value
    else fail "${context} must be a positive integer";

  requireNonNegative = context: value:
    if builtins.isInt value && value >= 0
    then value
    else fail "${context} must be a non-negative integer";

  requireBoundedPositive = context: maximum: value:
    if builtins.isInt value && value > 0 && value <= maximum
    then value
    else fail "${context} must be between 1 and ${builtins.toString maximum}";

  requireBoundedNonNegative = context: maximum: value:
    if builtins.isInt value && value >= 0 && value <= maximum
    then value
    else fail "${context} must be between 0 and ${builtins.toString maximum}";

  requireEnumString = context: value:
    if builtins.isString value && builtins.stringLength value <= maxStringLength
    then value
    else fail "${context} must be a string of at most ${builtins.toString maxStringLength} bytes";

  requireBoundedString = context: value:
    if
      builtins.isString value
      && builtins.stringLength value > 0
      && builtins.stringLength value <= 1048576
    then value
    else fail "${context} must be a non-empty string of at most 1048576 bytes";

  isLocalKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;

  isAsciiString = value:
    builtins.isString value
    && builtins.match "[[:cntrl:][:print:]]*" value != null;

  isDocumentKey = maximum: value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= maximum
    && builtins.match "[[:print:]]+" value != null;

  requireLocalKey = context: value:
    if isLocalKey value
    then value
    else fail "${context} must be a version-1 local key";

  isDigest = value:
    builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;

  isInterfaceKey = value:
    builtins.isAttrs value
    && builtins.attrNames value == ["abi" "descriptor" "name"]
    && builtins.isInt value.abi
    && value.abi > 0
    && value.abi <= 4294967295
    && builtins.isString value.name
    && builtins.stringLength value.name <= 128
    && builtins.match "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+" value.name != null
    && isDigest value.descriptor;

  isEnvironmentId = value:
    builtins.isAttrs value
    && builtins.attrNames value == ["authority" "key" "stage"]
    && isLocalKey value.authority
    && isLocalKey value.key
    && builtins.elem value.stage [
      "build"
      "initrd"
      "host"
      "system-container"
      "user"
      "application-container"
    ];

  isInstanceId = value:
    builtins.isAttrs value
    && builtins.attrNames value == ["environment" "key"]
    && isEnvironmentId value.environment
    && isLocalKey value.key;

  isResourceId = value:
    builtins.isAttrs value
    && builtins.attrNames value == ["key" "provider"]
    && isInstanceId value.provider
    && isLocalKey value.key;

  matchesSyntax = syntax: value:
    if syntax == null
    then true
    else if syntax == "local-key-v1"
    then
      builtins.stringLength value
      > 0
      && builtins.stringLength value <= 128
      && builtins.match "[A-Za-z0-9._-]+" value != null
    else if syntax == "qualified-name-v1"
    then
      builtins.stringLength value
      <= 128
      && builtins.match "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+" value != null
    else if syntax == "execution-path-v1"
    then let
      splitComponents = builtins.filter builtins.isString (builtins.split "/" value);
      components =
        if splitComponents == []
        then []
        else builtins.tail splitComponents;
    in
      builtins.substring 0 1 value
      == "/"
      && (
        value
        == "/"
        || builtins.all (component: component != "" && component != "." && component != "..") components
      )
    else if syntax == "relative-path-v1"
    then let
      components = builtins.filter builtins.isString (builtins.split "/" value);
    in
      value
      != ""
      && builtins.substring 0 1 value != "/"
      && builtins.all (component: component != "" && component != "." && component != "..") components
    else fail "unsupported string syntax '${syntax}'";

  schemaTopLevelKind = schema:
    if schema.kind == "refined"
    then schemaTopLevelKind schema.value
    else if schema.kind == "boolean"
    then "boolean"
    else if schema.kind == "integer"
    then "number"
    else if builtins.elem schema.kind ["string" "string-enum"]
    then "string"
    else if schema.kind == "list"
    then "array"
    else if
      builtins.elem schema.kind [
        "map"
        "record"
        "document-record"
        "tagged-union"
        "artifact-reference"
        "resource-reference"
        "provider-assignment"
        "transaction-blob-reference"
        "operation-result-reference"
      ]
    then "object"
    else null;

  unwrapRefinedSchema = schema:
    if schema.kind == "refined"
    then unwrapRefinedSchema schema.value
    else schema;

  requirePath = context: value:
    if
      builtins.isList value
      && value != []
      && builtins.length value <= maxSchemaDepth
      && builtins.all isLocalKey value
    then value
    else fail "${context} must be a non-empty list of local keys";

  requirePattern = context: value: let
    characters =
      if builtins.isString value
      then builtins.genList (index: builtins.substring index 1 value) (builtins.stringLength value)
      else [];
    hasPair = first: second:
      builtins.any (index:
        builtins.elemAt characters index
        == first
        && builtins.elemAt characters (index + 1) == second)
      (builtins.genList (index: index) (builtins.length characters - 1));
    lexicalState =
      builtins.foldl' (
        state: character:
          if !state.valid
          then state
          else if state.escaped
          then {
            escaped = false;
            inherit (state) inClass;
            valid = builtins.elem character ["." "\\"];
          }
          else if character == "\\"
          then state // {escaped = true;}
          else if character == "[" && !state.inClass
          then state // {inClass = true;}
          else if character == "]" && state.inClass
          then state // {inClass = false;}
          else if !state.inClass && builtins.elem character ["^" "$"]
          then state // {valid = false;}
          else state
      ) {
        escaped = false;
        inClass = false;
        valid = true;
      }
      characters;
    portable =
      characters
      != []
      && builtins.match "[[:print:]]+" value != null
      && !(hasPair "(" "?")
      && !(hasPair "&" "&")
      && !(hasPair "~" "~")
      && !(hasPair "[" ".")
      && !(hasPair "[" "=")
      && lexicalState.valid
      && !lexicalState.escaped
      && !lexicalState.inClass;
    attempted =
      if portable && builtins.stringLength value <= maxPatternLength
      then builtins.tryEval (builtins.match value "")
      else {success = false;};
  in
    if attempted.success
    then value
    else fail "${context} must use the portable regular-expression subset and contain at most ${builtins.toString maxPatternLength} bytes";

  refinedBase = schema:
    if schema.kind == "refined"
    then refinedBase schema.value
    else schema;

  schemasAtPath = schema: path: let
    concrete = refinedBase schema;
  in
    if path == []
    then [concrete]
    else let
      field = builtins.head path;
      remaining = builtins.tail path;
      descend = candidate: schemasAtPath candidate remaining;
      variants =
        if concrete.kind == "tagged-union"
        then builtins.attrValues concrete.variants
        else if concrete.kind == "disjoint-union"
        then concrete.variants
        else [];
      variantPaths =
        builtins.map (
          variant: schemasAtPath variant path
        )
        variants;
      mergedTagSchema = let
        # A tagged union's discriminator is one logical closed enumeration;
        # variants serialize its members as independent singleton schemas.
        tagSchemas =
          builtins.map (
            variant: (unwrapRefinedSchema variant).fields.${concrete.tag}
          )
          variants;
        values = builtins.sort builtins.lessThan (builtins.concatLists (
          builtins.map (tagSchema: (unwrapRefinedSchema tagSchema).values) tagSchemas
        ));
      in {
        kind = "string-enum";
        inherit values;
      };
    in
      if builtins.elem concrete.kind ["record" "document-record"]
      then
        if builtins.hasAttr field concrete.fields
        then descend concrete.fields.${field}
        else []
      else if concrete.kind == "tagged-union" && path == [concrete.tag]
      then [mergedTagSchema]
      else if variants != [] && builtins.all (resolved: resolved != []) variantPaths
      then builtins.concatLists variantPaths
      else [];

  allSchemasAre = predicate: schemas:
    schemas != [] && builtins.all (schema: predicate (refinedBase schema)) schemas;

  isStringSchema = schema:
    builtins.elem schema.kind ["string" "string-enum"];

  isListSchema = schema:
    schema.kind == "list";

  schemasAcceptValue = schemas: value:
    schemas
    != []
    && builtins.all (
      schema: (builtins.tryEval (builtins.deepSeq (checkValue schema value) true)).success
    )
    schemas;

  sameSchemas = left: right:
    left
    != []
    && right != []
    && builtins.all (
      schema: builtins.any (candidate: candidate == schema) right
    )
    left
    && builtins.all (
      schema: builtins.any (candidate: candidate == schema) left
    )
    right;

  maximumCardinality = schema: let
    concrete = refinedBase schema;
  in
    if concrete.kind == "string"
    then concrete.max_length
    else if concrete.kind == "string-enum"
    then
      builtins.foldl' (
        maximum: value: let
          length = builtins.stringLength value;
        in
          if length > maximum
          then length
          else maximum
      )
      0
      concrete.values
    else if concrete.kind == "list"
    then concrete.max_items
    else if concrete.kind == "map"
    then concrete.max_entries
    else if builtins.elem concrete.kind ["record" "document-record"]
    then builtins.length (builtins.attrNames concrete.fields)
    else null;

  validateConstraint = context: baseSchema: constraint: let
    base = refinedBase baseSchema;
    checked =
      if builtins.isAttrs constraint && constraint ? kind && builtins.isString constraint.kind
      then constraint
      else fail "${context} must be a refinement constraint";
    exact = fields: requireAttrs context (["kind"] ++ fields) checked;
    incompatible = expected:
      fail "${context} is incompatible with its base schema; expected ${expected}";
    pathSchemas = label: path: let
      resolved = schemasAtPath base path;
    in
      if resolved == []
      then fail "${context}.${label} does not name a field present in every base-schema variant"
      else resolved;
  in
    if checked.kind == "string-pattern"
    then
      if isStringSchema base
      then (exact ["pattern"]) // {pattern = requirePattern "${context}.pattern" checked.pattern;}
      else incompatible "a string"
    else if checked.kind == "minimum-size"
    then let
      minimum = requireBoundedNonNegative "${context}.minimum" maxCollectionItems checked.minimum;
      maximum = maximumCardinality base;
    in
      if maximum == null
      then incompatible "a string or bounded collection"
      else if minimum > maximum
      then fail "${context}.minimum exceeds the base schema's maximum size"
      else (exact ["minimum"]) // {inherit minimum;}
    else if checked.kind == "integer-set"
    then let
      values = (exact ["values"]).values;
      sorted = builtins.sort (left: right: left < right) values;
    in
      if
        !builtins.isList values
        || values == []
        || builtins.any (value: !builtins.isInt value || value < -maxSafeInteger || value > maxSafeInteger) values
        || values != sorted
        || builtins.length values
        != builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
            name = builtins.toString value;
            value = true;
          })
          values)))
      then fail "${context}.values must be non-empty, sorted, unique canonical integers"
      else if base.kind != "integer"
      then incompatible "an integer"
      else if builtins.any (value: value < base.minimum || value > base.maximum) values
      then fail "${context}.values contains an integer outside the base schema bounds"
      else checked
    else if checked.kind == "map-keys-pattern"
    then
      if base.kind == "map"
      then (exact ["pattern"]) // {pattern = requirePattern "${context}.pattern" checked.pattern;}
      else incompatible "a map"
    else if checked.kind == "string-excludes"
    then let
      classes = uniqueSortedStrings "${context}.classes" (exact ["classes"]).classes;
      supported = ["ascii-control" "ascii-space" "ascii-whitespace" "line-break"];
    in
      if classes == [] || !(builtins.all (class: builtins.elem class supported) classes)
      then fail "${context}.classes must contain supported exclusion classes"
      else if !isStringSchema base
      then incompatible "a string"
      else checked // {inherit classes;}
    else if checked.kind == "at-most-one-non-null"
    then let
      fields = uniqueSortedStrings "${context}.fields" (exact ["fields"]).fields;
      missing = builtins.filter (field: !(builtins.hasAttr field (base.fields or {}))) fields;
    in
      if fields == [] || !(builtins.all isLocalKey fields)
      then fail "${context}.fields must contain local keys"
      else if !(builtins.elem base.kind ["record" "document-record"])
      then incompatible "a record"
      else if missing != []
      then fail "${context}.fields names absent base-schema fields: ${builtins.concatStringsSep ", " missing}"
      else checked // {inherit fields;}
    else if checked.kind == "unique-at"
    then let
      path = requirePath "${context}.path" (exact ["path"]).path;
      resolved = pathSchemas "path" path;
    in
      if allSchemasAre isListSchema resolved
      then checked // {inherit path;}
      else incompatible "a path to a list"
    else if checked.kind == "disjoint-at"
    then let
      fields = exact ["left" "right"];
      left = requirePath "${context}.left" fields.left;
      right = requirePath "${context}.right" fields.right;
      leftSchemas = pathSchemas "left" left;
      rightSchemas = pathSchemas "right" right;
      leftElements = builtins.map (schema: (refinedBase schema).element) leftSchemas;
      rightElements = builtins.map (schema: (refinedBase schema).element) rightSchemas;
    in
      if !(allSchemasAre isListSchema leftSchemas && allSchemasAre isListSchema rightSchemas)
      then incompatible "paths to lists"
      else if !sameSchemas leftElements rightElements
      then fail "${context} list paths use incompatible element schemas"
      else fields // {inherit left right;}
    else if checked.kind == "subset-unless"
    then let
      fields = exact ["subset" "superset" "unless_path" "unless_equals"];
      subset = requirePath "${context}.subset" fields.subset;
      superset = requirePath "${context}.superset" fields.superset;
      unlessPath = requirePath "${context}.unless_path" fields.unless_path;
      subsetSchemas = pathSchemas "subset" subset;
      supersetSchemas = pathSchemas "superset" superset;
      unlessSchemas = pathSchemas "unless_path" unlessPath;
      subsetElements = builtins.map (schema: (refinedBase schema).element) subsetSchemas;
      supersetElements = builtins.map (schema: (refinedBase schema).element) supersetSchemas;
    in
      if !(allSchemasAre isListSchema subsetSchemas && allSchemasAre isListSchema supersetSchemas)
      then incompatible "subset and superset paths to lists"
      else if !sameSchemas subsetElements supersetElements
      then fail "${context} subset and superset paths use incompatible element schemas"
      else if !schemasAcceptValue unlessSchemas fields.unless_equals
      then fail "${context}.unless_equals is not admitted by the unless_path schema"
      else
        fields
        // {
          inherit subset superset;
          unless_path = unlessPath;
        }
    else if checked.kind == "structured-document"
    then let
      fields = exact ["format_field" "document_field"];
      formatField = requireLocalKey "${context}.format_field" fields.format_field;
      documentField = requireLocalKey "${context}.document_field" fields.document_field;
      formatSchemas = schemasAtPath base [formatField];
      documentSchemas = schemasAtPath base [documentField];
    in
      if !(builtins.elem base.kind ["record" "document-record"])
      then incompatible "a record"
      else if !allSchemasAre isStringSchema formatSchemas
      then fail "${context}.format_field must name a string field"
      else if !allSchemasAre isListSchema documentSchemas
      then fail "${context}.document_field must name a list field"
      else
        fields
        // {
          format_field = formatField;
          document_field = documentField;
        }
    else fail "${context} has unsupported kind '${checked.kind}'";

  validateSchemaAt = depth: context: value: let
    schema =
      if builtins.isAttrs value && value ? kind && builtins.isString value.kind
      then value
      else fail "${context} must be an ability value schema";
    exact = allowed: requireAttrs context (["kind"] ++ allowed) schema;
  in
    if depth > maxSchemaDepth
    then failLimit "${context} exceeds ${builtins.toString maxSchemaDepth} structural levels"
    else if schema.kind == "boolean"
    then exact []
    else if schema.kind == "integer"
    then let
      checked = exact ["minimum" "maximum"];
    in
      if
        builtins.isInt checked.minimum
        && builtins.isInt checked.maximum
        && checked.minimum <= checked.maximum
        && checked.minimum >= -maxSafeInteger
        && checked.maximum <= maxSafeInteger
      then checked
      else fail "${context} has invalid integer bounds"
    else if schema.kind == "string"
    then let
      checked = exact ["max_length" "syntax"];
    in
      if
        !(
          builtins.isInt checked.max_length
          && checked.max_length > 0
          && checked.max_length <= maxStringLength
        )
      then fail "${context}.max_length must be between 1 and ${builtins.toString maxStringLength}"
      else if !(builtins.elem checked.syntax [null "local-key-v1" "qualified-name-v1" "execution-path-v1" "relative-path-v1"])
      then fail "${context}.syntax is unsupported"
      else checked
    else if schema.kind == "string-enum"
    then let
      checked = exact ["values"];
      values = uniqueSortedStrings "${context}.values" checked.values;
    in
      if values == []
      then fail "${context}.values must contain at least one value"
      else if builtins.length values > maxCollectionItems
      then failLimit "${context}.values exceeds ${builtins.toString maxCollectionItems} entries"
      else if values != checked.values
      then fail "${context}.values must be sorted and unique"
      else checked
    else if schema.kind == "list"
    then let
      checked = requireAttrs context ["kind" "element" "max_items" "unique" "canonical_order"] schema;
      unique = checked.unique or false;
      canonicalOrder = checked.canonical_order or false;
    in
      if !(checked ? element && checked ? max_items)
      then fail "${context} must define element and max_items"
      else if !builtins.isBool unique || !builtins.isBool canonicalOrder
      then fail "${context} list constraints must be Boolean"
      else if canonicalOrder && !unique
      then fail "${context}.canonical_order requires unique"
      else
        assert requireBoundedNonNegative "${context}.max_items" maxCollectionItems checked.max_items == checked.max_items;
          {
            kind = "list";
            element = validateSchemaAt (depth + 1) "${context}.element" checked.element;
            max_items = checked.max_items;
          }
          // (
            if unique
            then {inherit unique;}
            else {}
          )
          // (
            if canonicalOrder
            then {canonical_order = true;}
            else {}
          )
    else if schema.kind == "map"
    then let
      checked = exact ["key" "max_entries" "value"];
      key = requireAttrs "${context}.key" ["max_length" "syntax"] checked.key;
    in
      assert requireBoundedPositive "${context}.key.max_length" maxStringLength key.max_length == key.max_length;
      assert builtins.elem key.syntax [null "local-key-v1" "qualified-name-v1" "relative-path-v1"];
      assert requireBoundedNonNegative "${context}.max_entries" maxCollectionItems checked.max_entries == checked.max_entries;
        checked // {value = validateSchemaAt (depth + 1) "${context}.value" checked.value;}
    else if schema.kind == "record"
    then let
      checked = exact ["fields" "optional_fields"];
      fields =
        builtins.mapAttrs (
          name: nested:
            assert requireLocalKey "${context} field name" name == name;
              validateSchemaAt (depth + 1) "${context}.fields.${name}" nested
        )
        checked.fields;
      optionalFields = uniqueSortedStrings "${context}.optional_fields" checked.optional_fields;
      unknownOptional = builtins.filter (name: !(builtins.hasAttr name fields)) optionalFields;
    in
      if builtins.length (builtins.attrNames fields) + builtins.length optionalFields > maxCollectionItems
      then failLimit "${context} exceeds ${builtins.toString maxCollectionItems} field entries"
      else if unknownOptional != []
      then fail "${context} names unknown optional fields: ${builtins.concatStringsSep ", " unknownOptional}"
      else
        checked
        // {
          inherit fields;
          optional_fields = optionalFields;
        }
    else if schema.kind == "document-record"
    then let
      checked = exact ["key_max_length" "fields" "optional_fields"];
      keyMaxLength = requireBoundedPositive "${context}.key_max_length" maxStringLength checked.key_max_length;
      fieldNames = builtins.attrNames checked.fields;
      invalidFields = builtins.filter (name: !isDocumentKey keyMaxLength name) fieldNames;
      fields =
        builtins.mapAttrs (
          name: nested:
            validateSchemaAt (depth + 1) "${context}.fields.${name}" nested
        )
        checked.fields;
      optionalFields = uniqueSortedStrings "${context}.optional_fields" checked.optional_fields;
      invalidOptional = builtins.filter (name: !isDocumentKey keyMaxLength name) optionalFields;
      unknownOptional = builtins.filter (name: !(builtins.hasAttr name fields)) optionalFields;
    in
      if builtins.length fieldNames + builtins.length optionalFields > maxCollectionItems
      then failLimit "${context} exceeds ${builtins.toString maxCollectionItems} field entries"
      else if invalidFields != [] || invalidOptional != []
      then fail "${context} contains invalid document field names"
      else if unknownOptional != []
      then fail "${context} names unknown optional fields: ${builtins.concatStringsSep ", " unknownOptional}"
      else {
        kind = "document-record";
        key_max_length = keyMaxLength;
        inherit fields;
        optional_fields = optionalFields;
      }
    else if schema.kind == "tagged-union"
    then let
      checked = exact ["tag" "variants"];
      tag = requireLocalKey "${context}.tag" checked.tag;
      variantNames = builtins.attrNames checked.variants;
      variants =
        builtins.mapAttrs (
          name: nested: let
            variantName = requireLocalKey "${context} variant name" name;
            variant = validateSchemaAt (depth + 1) "${context}.variants.${name}" nested;
            concreteVariant = unwrapRefinedSchema variant;
            tagSchema = concreteVariant.fields.${tag} or null;
          in
            if
              concreteVariant.kind
              != "record"
              || tagSchema == null
              || tagSchema.kind != "string-enum"
              || tagSchema.values != [variantName]
              || builtins.elem tag concreteVariant.optional_fields
            then fail "${context} variant '${name}' must be a record whose '${tag}' field accepts exactly '${name}'"
            else variant
        )
        checked.variants;
    in
      if variantNames == []
      then fail "${context}.variants must contain at least one variant"
      else if builtins.length variantNames > maxCollectionItems
      then failLimit "${context}.variants exceeds ${builtins.toString maxCollectionItems} entries"
      else checked // {inherit tag variants;}
    else if schema.kind == "disjoint-union"
    then let
      checked = exact ["variants"];
      rawVariants =
        if checked ? variants && builtins.isList checked.variants
        then checked.variants
        else fail "${context}.variants must be a list";
      variants = builtins.genList (
        index:
          validateSchemaAt
          (depth + 1)
          "${context}.variants.${builtins.toString index}"
          (builtins.elemAt rawVariants index)
      ) (builtins.length rawVariants);
      kinds = builtins.map schemaTopLevelKind variants;
      canonicalKinds = uniqueSortedStrings "${context} variant JSON kinds" kinds;
    in
      if builtins.length variants < 2
      then fail "${context}.variants must contain at least two variants"
      else if builtins.any (kind: kind == null) kinds
      then fail "${context} variants must each admit one top-level JSON kind"
      else if kinds != canonicalKinds
      then fail "${context}.variants must use distinct canonical JSON-kind order"
      else {
        kind = "disjoint-union";
        inherit variants;
      }
    else if schema.kind == "optional"
    then let
      checked = exact ["value"];
    in
      checked // {value = validateSchemaAt (depth + 1) "${context}.value" checked.value;}
    else if schema.kind == "refined"
    then let
      checked = exact ["value" "constraints"];
      base = validateSchemaAt (depth + 1) "${context}.value" checked.value;
      constraints =
        if builtins.isList checked.constraints && checked.constraints != [] && builtins.length checked.constraints <= maxCollectionItems
        then builtins.genList (index: validateConstraint "${context}.constraints.${builtins.toString index}" base (builtins.elemAt checked.constraints index)) (builtins.length checked.constraints)
        else fail "${context}.constraints must be a non-empty bounded list";
    in {
      kind = "refined";
      value = base;
      inherit constraints;
    }
    else if
      builtins.elem schema.kind [
        "artifact-reference"
        "resource-reference"
        "provider-assignment"
        "transaction-blob-reference"
        "operation-result-reference"
      ]
    then exact []
    else fail "${context} has unsupported kind '${schema.kind}'";

  validateSchema = validateSchemaAt 1;

  requireSchema = context: value: validateSchema context value;

  uniqueSortedStrings = context: values: let
    checked =
      if builtins.isList values && builtins.length values <= maxCollectionItems
      then builtins.map (requireEnumString context) values
      else fail "${context} must be a list of at most ${builtins.toString maxCollectionItems} strings";
    sorted = builtins.sort builtins.lessThan checked;
    duplicate =
      (
        builtins.foldl' (
          state: value: {
            previous = value;
            hasPrevious = true;
            found = state.found || (state.hasPrevious && state.previous == value);
          }
        ) {
          previous = null;
          hasPrevious = false;
          found = false;
        }
        sorted
      )
      .found;
  in
    if duplicate
    then fail "${context} contains a duplicate value"
    else sorted;

  valueAtPath = path: value:
    builtins.foldl' (
      current: component:
        if builtins.isAttrs current && builtins.hasAttr component current
        then current.${component}
        else fail "refinement path '${builtins.concatStringsSep "." path}' is unavailable"
    )
    value
    path;

  distinctValues = values: let
    encoded = builtins.map builtins.toJSON values;
  in
    builtins.length encoded
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (item: {
        name = item;
        value = true;
      })
      encoded)));

  checkStructuredDocument = constraint: source: let
    nodes = source.${constraint.document_field};
    pathPrefix = length: path:
      builtins.genList (index: builtins.elemAt path index) length;
    nodesByPath = builtins.listToAttrs (builtins.map (node: {
        name = builtins.toJSON node.path;
        value = node;
      })
      nodes);
    root = nodesByPath.${builtins.toJSON []} or null;
    immediateChildren = parentPath:
      builtins.filter (node: let
        length = builtins.length node.path;
      in
        length == builtins.length parentPath + 1 && pathPrefix (length - 1) node.path == parentPath)
      nodes;
    parentsValid = builtins.all (node: let
      length = builtins.length node.path;
    in
      length
      == 0
      || (let
        parentPath = pathPrefix (length - 1) node.path;
        parent = nodesByPath.${builtins.toJSON parentPath} or null;
        segment = builtins.elemAt node.path (length - 1);
      in
        parent
        != null
        && (
          (segment.kind == "key" && parent.kind == "object")
          || (segment.kind == "index" && parent.kind == "array")
        )))
    nodes;
    arraysContiguous = builtins.all (node:
      node.kind
      != "array"
      || (let
        children = immediateChildren node.path;
        indices = builtins.sort (left: right: left < right) (builtins.map
          (child: (builtins.elemAt child.path (builtins.length child.path - 1)).value)
          children);
      in
        indices == builtins.genList (index: index) (builtins.length indices)))
    nodes;
    formatValid =
      source.${constraint.format_field}
      != "toml"
      || (root != null && root.kind == "object" && builtins.all (node: node.kind != "null") nodes);
  in
    nodes
    != []
    && distinctValues (builtins.map (node: node.path) nodes)
    && root != null
    && parentsValid
    && arraysContiguous
    && formatValid;

  constraintSatisfied = constraint: value:
    if constraint.kind == "string-pattern"
    then builtins.isString value && builtins.match constraint.pattern value != null
    else if constraint.kind == "minimum-size"
    then
      if builtins.isString value
      then builtins.stringLength value >= constraint.minimum
      else if builtins.isList value
      then builtins.length value >= constraint.minimum
      else if builtins.isAttrs value
      then builtins.length (builtins.attrNames value) >= constraint.minimum
      else false
    else if constraint.kind == "integer-set"
    then builtins.isInt value && builtins.elem value constraint.values
    else if constraint.kind == "map-keys-pattern"
    then builtins.isAttrs value && builtins.all (name: builtins.match constraint.pattern name != null) (builtins.attrNames value)
    else if constraint.kind == "string-excludes"
    then
      builtins.isString value
      && builtins.all (class:
        if class == "ascii-control"
        then builtins.match "[^[:cntrl:]]*" value != null
        else if class == "ascii-space"
        then builtins.match "[^ ]*" value != null
        else if class == "ascii-whitespace"
        then builtins.match "[^[:space:]]*" value != null
        else if class == "line-break"
        then builtins.match "[^\n\r]*" value != null
        else false)
      constraint.classes
    else if constraint.kind == "at-most-one-non-null"
    then builtins.length (builtins.filter (field: (value.${field} or null) != null) constraint.fields) <= 1
    else if constraint.kind == "unique-at"
    then distinctValues (valueAtPath constraint.path value)
    else if constraint.kind == "disjoint-at"
    then let
      right = valueAtPath constraint.right value;
    in
      builtins.all (item: !(builtins.elem item right)) (valueAtPath constraint.left value)
    else if constraint.kind == "subset-unless"
    then
      (
        valueAtPath constraint.unless_path value
        == constraint.unless_equals
        || (let
          superset = valueAtPath constraint.superset value;
        in
          builtins.all (item: builtins.elem item superset) (valueAtPath constraint.subset value))
      )
    else if constraint.kind == "structured-document"
    then checkStructuredDocument constraint value
    else false;

  constraintsSatisfied = constraints: value:
    builtins.all (constraint: constraintSatisfied constraint value) constraints;

  checkValueUnchecked = schema: value: let
    invalid = expected: fail "expected ${expected}, got ${builtins.typeOf value}";
    checkRecord = let
      valueSet =
        if builtins.isAttrs value
        then value
        else invalid "a record";
      fieldNames = builtins.attrNames schema.fields;
      optionalNames = schema.optional_fields;
      requiredNames = builtins.filter (name: !(builtins.elem name optionalNames)) fieldNames;
      missing = builtins.filter (name: !(builtins.hasAttr name valueSet)) requiredNames;
      unexpected = builtins.filter (name: !(builtins.elem name fieldNames)) (builtins.attrNames valueSet);
    in
      if missing != []
      then fail "record is missing required fields: ${builtins.concatStringsSep ", " missing}"
      else if unexpected != []
      then fail "record has unsupported fields: ${builtins.concatStringsSep ", " unexpected}"
      else builtins.mapAttrs (name: _: checkValue schema.fields.${name} valueSet.${name}) valueSet;
  in
    if schema.kind == "boolean"
    then
      if builtins.isBool value
      then value
      else invalid "a Boolean"
    else if schema.kind == "integer"
    then
      if !builtins.isInt value
      then invalid "an integer"
      else if value < schema.minimum || value > schema.maximum
      then fail "integer ${builtins.toString value} is outside [${builtins.toString schema.minimum}, ${builtins.toString schema.maximum}]"
      else value
    else if schema.kind == "string"
    then
      if !builtins.isString value
      then invalid "a string"
      else if builtins.stringLength value > schema.max_length
      then fail "string exceeds max_length ${builtins.toString schema.max_length}"
      else if !matchesSyntax schema.syntax value
      then fail "string does not match ${schema.syntax}"
      else value
    else if schema.kind == "string-enum"
    then
      if builtins.isString value && builtins.elem value schema.values
      then value
      else fail "value is not one of: ${builtins.concatStringsSep ", " schema.values}"
    else if schema.kind == "list"
    then
      if !builtins.isList value
      then invalid "a list"
      else if builtins.length value > schema.max_items
      then fail "list exceeds max_items ${builtins.toString schema.max_items}"
      else let
        checked = builtins.map (checkValue schema.element) value;
        encoded = builtins.map builtins.toJSON checked;
        unique =
          builtins.length encoded
          == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (item: {
              name = item;
              value = true;
            })
            encoded)));
        ordered = encoded == builtins.sort builtins.lessThan encoded;
      in
        if (schema.unique or false) && !unique
        then fail "list elements must be unique"
        else if (schema.canonical_order or false) && !ordered
        then fail "list elements must be in canonical order"
        else checked
    else if schema.kind == "map"
    then let
      entries =
        if builtins.isAttrs value
        then value
        else invalid "a map";
      names = builtins.attrNames entries;
      invalidKeys =
        builtins.filter (
          name:
            !isAsciiString name
            || builtins.stringLength name > schema.key.max_length
            || !matchesSyntax schema.key.syntax name
        )
        names;
    in
      if builtins.length names > schema.max_entries
      then fail "map exceeds max_entries ${builtins.toString schema.max_entries}"
      else if invalidKeys != []
      then fail "map contains invalid keys: ${builtins.concatStringsSep ", " invalidKeys}"
      else builtins.mapAttrs (_: checkValue schema.value) entries
    else if schema.kind == "record"
    then checkRecord
    else if schema.kind == "document-record"
    then checkRecord
    else if schema.kind == "tagged-union"
    then let
      valueSet =
        if builtins.isAttrs value
        then value
        else invalid "a tagged union record";
      tagValue = valueSet.${schema.tag} or null;
    in
      if !builtins.isString tagValue || !(builtins.hasAttr tagValue schema.variants)
      then fail "tag '${schema.tag}' does not select a declared variant"
      else checkValue schema.variants.${tagValue} valueSet
    else if schema.kind == "disjoint-union"
    then let
      valueKind =
        if builtins.isBool value
        then "boolean"
        else if builtins.isInt value || builtins.isFloat value
        then "number"
        else if builtins.isString value
        then "string"
        else if builtins.isList value
        then "array"
        else if builtins.isAttrs value
        then "object"
        else null;
      matching = builtins.filter (variant: schemaTopLevelKind variant == valueKind) schema.variants;
    in
      if valueKind == null || builtins.length matching != 1
      then fail "value has no matching disjoint-union variant"
      else checkValue (builtins.head matching) value
    else if schema.kind == "optional"
    then
      if value == null
      then null
      else checkValue schema.value value
    else if schema.kind == "refined"
    then let
      checked = checkValue schema.value value;
      failed = builtins.filter (constraint: !(constraintSatisfied constraint checked)) schema.constraints;
    in
      if failed == []
      then checked
      else fail "value does not satisfy refinement '${(builtins.head failed).kind}'"
    else if
      builtins.elem schema.kind [
        "artifact-reference"
        "resource-reference"
        "provider-assignment"
        "transaction-blob-reference"
        "operation-result-reference"
      ]
    then
      if schema.kind == "artifact-reference"
      then
        if
          builtins.isAttrs value
          && builtins.attrNames value == ["_type" "closure" "content" "nar_hash" "store_path"]
          && value._type == "aos-artifact-reference"
          && isDigest value.content
          && isDigest value.nar_hash
          && isDigest value.closure
          && builtins.isString value.store_path
        then value
        else invalid "an artifact-reference"
      else if schema.kind == "resource-reference"
      then
        if
          builtins.isAttrs value
          && builtins.attrNames value == ["_type" "interface" "lifetime" "operations" "resource"]
          && value._type == "aos-resource-reference"
          && isInterfaceKey value.interface
          && isResourceId value.resource
          && value.operations == uniqueSortedStrings "resource operations" value.operations
          && builtins.all isLocalKey value.operations
          && builtins.elem value.lifetime lifetime.values
        then value
        else invalid "a resource-reference"
      else if schema.kind == "provider-assignment"
      then fail "provider-assignment values are unavailable during pure authoring"
      else if schema.kind == "transaction-blob-reference"
      then fail "transaction-blob-reference values must originate from a runtime operation output"
      else fail "operation-result-reference values are unavailable until scoped producer normalization is implemented"
    else fail "unsupported schema kind '${schema.kind}'";

  checkValue = schema: value:
    checkValueUnchecked (validateSchema "value schema" schema) value;
in rec {
  boolean = {kind = "boolean";};

  integer = args: let
    checked = requireAttrs "integer schema" ["minimum" "maximum"] args;
    minimum = checked.minimum;
    maximum = checked.maximum;
  in
    if
      !builtins.isInt minimum
      || !builtins.isInt maximum
      || minimum > maximum
      || minimum < -maxSafeInteger
      || maximum > maxSafeInteger
    then fail "integer bounds must be ordered canonical JSON integers"
    else {
      inherit minimum maximum;
      kind = "integer";
    };

  string = args: let
    checked = requireAttrs "string schema" ["maxLength" "syntax"] args;
    syntax = checked.syntax or null;
  in
    if !(builtins.elem syntax [null "local-key-v1" "qualified-name-v1" "execution-path-v1" "relative-path-v1"])
    then fail "string schema has unsupported syntax"
    else {
      kind = "string";
      max_length = requireBoundedPositive "string maxLength" maxStringLength checked.maxLength;
      inherit syntax;
    };

  enum = values: {
    kind = "string-enum";
    values = let
      checked = uniqueSortedStrings "enum values" values;
    in
      if checked == []
      then fail "enum values must contain at least one value"
      else checked;
  };

  list = args: let
    checked = requireAttrs "list schema" ["element" "maxItems" "unique" "canonicalOrder"] args;
    unique = checked.unique or false;
    canonicalOrder = checked.canonicalOrder or false;
    candidate =
      {
        kind = "list";
        element = checked.element;
        max_items = requireBoundedNonNegative "list maxItems" maxCollectionItems checked.maxItems;
      }
      // (
        if unique
        then {inherit unique;}
        else {}
      )
      // (
        if canonicalOrder
        then {canonical_order = true;}
        else {}
      );
  in
    if !builtins.isBool unique || !builtins.isBool canonicalOrder
    then fail "list constraints must be Boolean"
    else if canonicalOrder && !unique
    then fail "list canonicalOrder requires unique"
    else validateSchema "list schema" candidate;

  map = args: let
    checked = requireAttrs "map schema" ["keyMaxLength" "keySyntax" "maxEntries" "value"] args;
    keySyntax = checked.keySyntax or null;
    candidate = {
      kind = "map";
      key = {
        max_length = requireBoundedPositive "map keyMaxLength" maxStringLength checked.keyMaxLength;
        syntax = keySyntax;
      };
      max_entries = requireBoundedNonNegative "map maxEntries" maxCollectionItems checked.maxEntries;
      value = checked.value;
    };
  in
    if !(builtins.elem keySyntax [null "local-key-v1" "qualified-name-v1" "execution-path-v1" "relative-path-v1"])
    then fail "map schema has unsupported key syntax"
    else validateSchema "map schema" candidate;

  record = args: let
    checked = requireAttrs "record schema" ["fields" "optional"] args;
    fields =
      builtins.mapAttrs (
        name: nested:
          assert requireLocalKey "record field name" name == name;
            requireSchema "record field '${name}'" nested
      )
      checked.fields;
    optional = uniqueSortedStrings "optional field names" (checked.optional or []);
    unknownOptional = builtins.filter (name: !(builtins.hasAttr name fields)) optional;
  in
    if unknownOptional != []
    then fail "optional fields are not declared: ${builtins.concatStringsSep ", " unknownOptional}"
    else
      validateSchema "record schema" {
        kind = "record";
        inherit fields;
        optional_fields = optional;
      };

  documentRecord = args: let
    checked = requireAttrs "document-record schema" ["keyMaxLength" "fields" "optional"] args;
    keyMaxLength = requireBoundedPositive "document-record keyMaxLength" maxStringLength checked.keyMaxLength;
    fields =
      builtins.mapAttrs (
        name: nested:
          if isDocumentKey keyMaxLength name
          then requireSchema "document-record field '${name}'" nested
          else fail "document-record field '${name}' is not a bounded printable document key"
      )
      checked.fields;
    optional = uniqueSortedStrings "optional document field names" (checked.optional or []);
    invalidOptional = builtins.filter (name: !isDocumentKey keyMaxLength name) optional;
    unknownOptional = builtins.filter (name: !(builtins.hasAttr name fields)) optional;
  in
    if invalidOptional != []
    then fail "optional document fields contain invalid names"
    else if unknownOptional != []
    then fail "optional document fields are not declared: ${builtins.concatStringsSep ", " unknownOptional}"
    else
      validateSchema "document-record schema" {
        kind = "document-record";
        key_max_length = keyMaxLength;
        inherit fields;
        optional_fields = optional;
      };

  taggedUnion = args: let
    checked = requireAttrs "tagged-union schema" ["tag" "variants"] args;
    candidate = {
      kind = "tagged-union";
      tag = requireLocalKey "tagged-union tag" checked.tag;
      variants =
        builtins.mapAttrs (
          name: nested:
            assert requireLocalKey "tagged-union variant name" name == name;
              requireSchema "tagged-union variant '${name}'" nested
        )
        checked.variants;
    };
  in
    validateSchema "tagged-union schema" candidate;

  disjointUnion = variants: let
    rawVariants =
      if builtins.isList variants
      then variants
      else fail "disjoint-union variants must be a list";
    normalized = builtins.genList (
      index:
        requireSchema
        "disjoint-union variant ${builtins.toString index}"
        (builtins.elemAt rawVariants index)
    ) (builtins.length rawVariants);
    unsupported = builtins.filter (variant: schemaTopLevelKind variant == null) normalized;
    canonical =
      builtins.sort (
        left: right: schemaTopLevelKind left < schemaTopLevelKind right
      )
      normalized;
  in
    if unsupported != []
    then fail "disjoint-union variants must each admit one top-level JSON kind"
    else
      validateSchema "disjoint-union schema" {
        kind = "disjoint-union";
        variants = canonical;
      };

  optional = value:
    validateSchema "optional schema" {
      kind = "optional";
      inherit value;
    };

  refined = args: let
    checked = requireAttrs "refined schema" ["value" "constraints"] args;
  in
    validateSchema "refined schema" {
      kind = "refined";
      inherit (checked) value constraints;
    };

  artifactReference = {kind = "artifact-reference";};
  resourceReference = {kind = "resource-reference";};
  providerAssignment = {kind = "provider-assignment";};
  transactionBlobReference = {kind = "transaction-blob-reference";};
  operationResultReference = {kind = "operation-result-reference";};

  topLevelKind = schema:
    schemaTopLevelKind (validateSchema "top-level JSON kind" schema);

  inherit checkValue constraintsSatisfied validateSchema;
}
