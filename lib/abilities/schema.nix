##! lib/abilities/schema.nix - Portable ability value schemas.
##!
##! Constructors in this file emit closed, JSON-serializable descriptions.
##! The same vocabulary is decoded by the native ability validator. These
##! helpers also validate concrete Nix values early, before serialization.
let
  fail = message: throw "ability schema: ${message}";

  maxSafeInteger = 9007199254740991;
  maxStringLength = 1048576;
  maxCollectionItems = 2000000;
  maxSchemaDepth = 64;

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
    else fail "unsupported string syntax '${syntax}'";

  validateSchemaAt = depth: context: value: let
    schema =
      if builtins.isAttrs value && value ? kind && builtins.isString value.kind
      then value
      else fail "${context} must be an ability value schema";
    exact = allowed: requireAttrs context (["kind"] ++ allowed) schema;
  in
    if depth > maxSchemaDepth
    then fail "${context} exceeds ${builtins.toString maxSchemaDepth} structural levels"
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
      else if !(builtins.elem checked.syntax [null "local-key-v1" "qualified-name-v1"])
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
      then fail "${context}.values exceeds ${builtins.toString maxCollectionItems} entries"
      else if values != checked.values
      then fail "${context}.values must be sorted and unique"
      else checked
    else if schema.kind == "list"
    then let
      checked = exact ["element" "max_items"];
    in
      assert requireBoundedNonNegative "${context}.max_items" maxCollectionItems checked.max_items == checked.max_items;
        checked // {element = validateSchemaAt (depth + 1) "${context}.element" checked.element;}
    else if schema.kind == "map"
    then let
      checked = exact ["key" "max_entries" "value"];
      key = requireAttrs "${context}.key" ["max_length" "syntax"] checked.key;
    in
      assert requireBoundedPositive "${context}.key.max_length" maxStringLength key.max_length == key.max_length;
      assert builtins.elem key.syntax [null "local-key-v1" "qualified-name-v1"];
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
      then fail "${context} exceeds ${builtins.toString maxCollectionItems} field entries"
      else if unknownOptional != []
      then fail "${context} names unknown optional fields: ${builtins.concatStringsSep ", " unknownOptional}"
      else
        checked
        // {
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
            tagSchema = variant.fields.${tag} or null;
          in
            if
              variant.kind
              != "record"
              || tagSchema == null
              || tagSchema.kind != "string-enum"
              || tagSchema.values != [variantName]
              || builtins.elem tag variant.optional_fields
            then fail "${context} variant '${name}' must be a record whose '${tag}' field accepts exactly '${name}'"
            else variant
        )
        checked.variants;
    in
      if variantNames == []
      then fail "${context}.variants must contain at least one variant"
      else if builtins.length variantNames > maxCollectionItems
      then fail "${context}.variants exceeds ${builtins.toString maxCollectionItems} entries"
      else checked // {inherit tag variants;}
    else if schema.kind == "optional"
    then let
      checked = exact ["value"];
    in
      checked // {value = validateSchemaAt (depth + 1) "${context}.value" checked.value;}
    else if
      builtins.elem schema.kind [
        "artifact-reference"
        "resource-reference"
        "provider-assignment"
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
      ).found;
  in
    if duplicate
    then fail "${context} contains a duplicate value"
    else sorted;

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
      else builtins.map (checkValue schema.element) value
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
    else if schema.kind == "optional"
    then
      if value == null
      then null
      else checkValue schema.value value
    else if
      builtins.elem schema.kind [
        "artifact-reference"
        "resource-reference"
        "provider-assignment"
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
          && builtins.elem value.lifetime ["attempt" "transaction" "instance" "persistent"]
        then value
        else invalid "a resource-reference"
      else if schema.kind == "provider-assignment"
      then fail "provider-assignment values are unavailable during pure authoring"
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
    if !(builtins.elem syntax [null "local-key-v1" "qualified-name-v1"])
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
    checked = requireAttrs "list schema" ["element" "maxItems"] args;
    candidate = {
      kind = "list";
      element = checked.element;
      max_items = requireBoundedNonNegative "list maxItems" maxCollectionItems checked.maxItems;
    };
  in
    validateSchema "list schema" candidate;

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
    if !(builtins.elem keySyntax [null "local-key-v1" "qualified-name-v1"])
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

  optional = value:
    validateSchema "optional schema" {
      kind = "optional";
      inherit value;
    };

  artifactReference = {kind = "artifact-reference";};
  resourceReference = {kind = "resource-reference";};
  providerAssignment = {kind = "provider-assignment";};
  operationResultReference = {kind = "operation-result-reference";};

  inherit checkValue validateSchema;
}
