##! Portable ability types for the AOS module system.
##!
##! Each constructor returns an ordinary AOS option type with an additional
##! `_abilitySchema` projection. Module evaluation uses the option type while
##! publication, native validation, editors, and generated documentation use
##! the closed schema projection. Interface authors therefore declare a field
##! once instead of maintaining parallel Nix and wire schemas.
{
  mkOption,
  moduleTypes,
  schemas,
}: let
  schemaDocumentType = schema: let
    nested = value: schemaDocumentType value;
  in
    if schema.kind == "boolean"
    then {kind = "bool";}
    else if schema.kind == "integer"
    then {
      kind = "integer";
      min = schema.minimum;
      max = schema.maximum;
    }
    else if schema.kind == "string"
    then {
      kind = "string";
      pattern = schema.syntax;
      max_length = schema.max_length;
    }
    else if schema.kind == "string-enum"
    then {
      kind = "enum";
      values = builtins.map (value: {
        inherit value;
        description = [];
      }) schema.values;
    }
    else if schema.kind == "list"
    then {
      kind = "list";
      element = nested schema.element;
      unique = false;
    }
    else if schema.kind == "map"
    then {
      kind = "attrs-of";
      value = nested schema.value;
      placeholder = "name";
    }
    else if schema.kind == "record"
    then {
      kind = "submodule";
      fields = builtins.mapAttrs (_: nested) schema.fields;
      open = false;
    }
    else if schema.kind == "tagged-union"
    then {
      kind = "one-of";
      alternatives = builtins.map nested (builtins.attrValues schema.variants);
    }
    else if schema.kind == "optional"
    then {
      kind = "nullable";
      value = nested schema.value;
    }
    else {
      kind = "opaque";
      signature = schema.kind;
    };

  validates = schema: value:
    (builtins.tryEval (builtins.deepSeq (schemas.checkValue schema value) true)).success;

  checkedSchema = context: schema:
    schemas.validateSchema "${context} ability option type" schema;

  decorate = context: schema: optionType: let
    normalized = checkedSchema context schema;
  in
    optionType
    // {
      _abilitySchema = normalized;
      _aosDocType = schemaDocumentType normalized;
    };

  normalizedField = name: value: let
    definition =
      if moduleTypes.optionType.check value
      then {type = value;}
      else if builtins.isAttrs value && value ? type
      then value
      else throw "ability record field '${name}' must be an ability type or an option declaration";
    fieldType = definition.type;
  in
    if !(fieldType ? _abilitySchema)
    then throw "ability record field '${name}' does not use lib.abilities.types"
    else {
      inherit fieldType;
      optional = definition.optional or (definition ? default);
      option = mkOption (builtins.removeAttrs definition ["optional"]);
    };

  localKeyPattern = "[A-Za-z0-9._-]+";
  qualifiedNamePattern = "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+";

  syntaxMatches = syntax: value:
    if syntax == null
    then true
    else if syntax == "local-key-v1"
    then builtins.match localKeyPattern value != null
    else if syntax == "qualified-name-v1"
    then builtins.match qualifiedNamePattern value != null
    else false;
in rec {
  ## Returns the canonical portable schema carried by an ability option type.
  schemaOf = context: abilityType:
    if moduleTypes.optionType.check abilityType && abilityType ? _abilitySchema
    then checkedSchema context abilityType._abilitySchema
    else throw "${context} must use an option type from lib.abilities.types";

  ## Converts a closed portable schema into a normal AOS option type.
  ##
  ## Prefer the structural constructors below for authored module options;
  ## this function is the generic decoder boundary for published schemas.
  fromSchema = schema: let
    normalized = checkedSchema "decoded" schema;
    base = moduleTypes.mkOptionType {
      name = "ability-${normalized.kind}";
      description = "value satisfying the ${normalized.kind} ability schema";
      check = validates normalized;
      aosDocType = schemaDocumentType normalized;
    };
  in
    decorate "decoded" normalized base;

  boolean = decorate "boolean" schemas.boolean moduleTypes.bool;

  integer = args: let
    schema = schemas.integer args;
    base = moduleTypes.addCheck moduleTypes.int (value:
      value >= schema.minimum && value <= schema.maximum);
  in
    decorate "integer" schema base;

  string = args: let
    schema = schemas.string args;
    base = moduleTypes.addCheck moduleTypes.str (value:
      builtins.stringLength value <= schema.max_length
      && syntaxMatches schema.syntax value);
  in
    decorate "string" schema base;

  enum = values: let
    schema = schemas.enum values;
  in
    decorate "enumeration" schema (moduleTypes.enum schema.values);

  list = {
    element,
    maxItems,
  }: let
    elementSchema = schemaOf "ability list element" element;
    schema = schemas.list {
      inherit maxItems;
      element = elementSchema;
    };
    base = moduleTypes.addCheck (moduleTypes.listOf element) (value:
      builtins.length value <= schema.max_items);
  in
    decorate "list" schema base;

  map = {
    keyMaxLength,
    keySyntax ? null,
    maxEntries,
    value,
  }: let
    valueSchema = schemaOf "ability map value" value;
    schema = schemas.map {
      inherit keyMaxLength keySyntax maxEntries;
      value = valueSchema;
    };
    validKey = key:
      builtins.stringLength key <= schema.key.max_length
      && syntaxMatches schema.key.syntax key;
    base = moduleTypes.addCheck (moduleTypes.attrsOf value) (entries:
      builtins.length (builtins.attrNames entries) <= schema.max_entries
      && builtins.all validKey (builtins.attrNames entries));
  in
    decorate "map" schema base;

  record = {
    fields,
    optional ? [],
  }: let
    normalizedFields = builtins.mapAttrs normalizedField fields;
    inferredOptional = builtins.filter
      (name: normalizedFields.${name}.optional)
      (builtins.attrNames normalizedFields);
    optionalFields = builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = true;
      }) (optional ++ inferredOptional)));
    schema = schemas.record {
      fields = builtins.mapAttrs
        (_: field: schemaOf "ability record field" field.fieldType)
        normalizedFields;
      optional = optionalFields;
    };
    submoduleType = moduleTypes.submodule {
      _file = "<lib.abilities.types.record>";
      _module.strict = true;
      options = builtins.mapAttrs (_: field: field.option) normalizedFields;
    };
    base = submoduleType // {
      merge = location: definitions:
        builtins.removeAttrs (submoduleType.merge location definitions) ["_module"];
    };
  in
    decorate "record" schema base;

  taggedUnion = {
    tag,
    variants,
  }: let
    variantSchemas = builtins.mapAttrs
      (name: variant: schemaOf "ability tagged-union variant '${name}'" variant)
      variants;
    schema = schemas.taggedUnion {
      inherit tag;
      variants = variantSchemas;
    };
  in
    fromSchema schema;

  optional = value: let
    schema = schemas.optional (schemaOf "optional ability value" value);
  in
    decorate "optional" schema (moduleTypes.nullOr value);

  artifactReference = fromSchema schemas.artifactReference;
  resourceReference = fromSchema schemas.resourceReference;
  providerAssignment = fromSchema schemas.providerAssignment;
  operationResultReference = fromSchema schemas.operationResultReference;
}
