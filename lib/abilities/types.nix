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
      values =
        builtins.map (value: {
          inherit value;
          description = [];
        })
        schema.values;
    }
    else if schema.kind == "list"
    then {
      kind = "list";
      element = nested schema.element;
      unique = schema.unique or false;
      canonical_order = schema.canonical_order or false;
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
    else if schema.kind == "document-record"
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
    else if schema.kind == "disjoint-union"
    then {
      kind = "one-of";
      alternatives = builtins.map nested schema.variants;
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
      merge = location: definitions: let
        merged = optionType.merge location definitions;
      in
        if optionType.check merged
        then merged
        else throw "The option '${builtins.concatStringsSep "." location}' is not valid for ${context}.";
    };

  normalizedField = name: value: let
    definition =
      if moduleTypes.optionType.check value
      then {type = value;}
      else if builtins.isAttrs value && value ? type
      then value
      else throw "ability record field '${name}' must be an ability type or an option declaration";
    fieldType = definition.type;
    omittable = definition.optional or false;
    hasDefault = definition ? default;
    optionDefinition = builtins.removeAttrs definition ["optional"];
  in
    if !(fieldType ? _abilitySchema)
    then throw "ability record field '${name}' does not use lib.abilities.types"
    else {
      inherit fieldType;
      optional = omittable || hasDefault;
      option = mkOption (
        if omittable && !hasDefault
        then
          optionDefinition
          // {
            type = moduleTypes.nullOr fieldType;
            default = null;
          }
        else optionDefinition
      );
    };

  localKeyPattern = "[A-Za-z0-9._-]+";
  qualifiedNamePattern = "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+";

  isExecutionPath = value: let
    splitComponents =
      if builtins.isString value
      then builtins.filter builtins.isString (builtins.split "/" value)
      else [];
    components =
      if splitComponents == []
      then []
      else builtins.tail splitComponents;
  in
    builtins.isString value
    && builtins.stringLength value <= 4096
    && builtins.substring 0 1 value == "/"
    && (
      value == "/"
      || builtins.all (component: component != "" && component != "." && component != "..") components
    );

  syntaxMatches = syntax: value:
    if syntax == null
    then true
    else if syntax == "local-key-v1"
    then builtins.match localKeyPattern value != null
    else if syntax == "qualified-name-v1"
    then builtins.match qualifiedNamePattern value != null
    else if syntax == "execution-path-v1"
    then isExecutionPath value
    else false;

  strictRecordType = file: fields: let
    submoduleType = moduleTypes.submodule {
      _file = file;
      _module.strict = true;
      options = builtins.mapAttrs (_: type: mkOption {inherit type;}) fields;
    };
  in
    submoduleType
    // {
      merge = location: definitions:
        builtins.removeAttrs (submoduleType.merge location definitions) ["_module"];
    };

  decorateRecord = context: file: schema: normalizedFields: optionalFields: let
    submoduleType = moduleTypes.submodule {
      _file = file;
      _module.strict = true;
      options = builtins.mapAttrs (_: field: field.option) normalizedFields;
    };
    base =
      submoduleType
      // {
        merge = location: definitions: let
          merged = builtins.removeAttrs (submoduleType.merge location definitions) ["_module"];
          omittedNullFields = builtins.filter (
            name: builtins.elem name optionalFields && merged.${name} == null
          ) (builtins.attrNames merged);
        in
          builtins.removeAttrs merged omittedNullFields;
      };
  in
    decorate context schema base;

  digestType =
    moduleTypes.addCheck moduleTypes.str (value:
      builtins.match "sha256:[0-9a-f]{64}" value != null);
  localKeyType = moduleTypes.addCheck moduleTypes.str (syntaxMatches "local-key-v1");
  packageNameType = moduleTypes.addCheck moduleTypes.str (value:
    builtins.stringLength value
    > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9+._-]+" value != null);
  declarationKeyType = moduleTypes.addCheck moduleTypes.str (value:
    builtins.stringLength value
    <= 257
    && builtins.match "[A-Za-z0-9+._-]+:[A-Za-z0-9._-]+" value != null);
  qualifiedNameType = moduleTypes.addCheck moduleTypes.str (syntaxMatches "qualified-name-v1");
  stageType = moduleTypes.enum ["build" "initrd" "host" "system-container" "user" "application-container"];
  interfaceKeyType = strictRecordType "<lib.abilities.types.interface-key>" {
    name = qualifiedNameType;
    abi = moduleTypes.addCheck moduleTypes.int (value: value > 0 && value <= 4294967295);
    descriptor = digestType;
  };
  environmentType = strictRecordType "<lib.abilities.types.environment>" {
    authority = localKeyType;
    key = localKeyType;
    stage = stageType;
  };
  instanceType = strictRecordType "<lib.abilities.types.instance>" {
    environment = environmentType;
    key = localKeyType;
  };
  resourceIdType = strictRecordType "<lib.abilities.types.resource-id>" {
    provider = instanceType;
    key = localKeyType;
  };
  packageOutputType = moduleTypes.mkOptionType {
    name = "package output selector";
    description = "closed symbolic package output selector";
    check = value:
      builtins.isAttrs value
      && builtins.attrNames value == ["_type" "output" "package"]
      && value._type == "aos-package-output-selector"
      && localKeyType.check value.package
      && localKeyType.check value.output;
    merge = moduleTypes.mergeEqualOption;
  };
  relativePathType = moduleTypes.addCheck moduleTypes.str (value: let
    components = builtins.filter builtins.isString (builtins.split "/" value);
  in
    value
    != ""
    && builtins.stringLength value <= 4096
    && builtins.substring 0 1 value != "/"
    && builtins.all (component: component != "" && component != "." && component != "..") components);

  specialType = context: schema: fields:
    (decorate context schema (strictRecordType "<lib.abilities.types.${context}>" fields))
    // {
      _aosDocType = {
        kind = "submodule";
        fields = builtins.mapAttrs (_: type:
          type._aosDocType
          or {
            kind = type.name or "opaque";
          })
        fields;
        open = false;
      };
    };
  operationResultReferenceType =
    (specialType "operation-result-reference" schemas.operationResultReference {
      _type = moduleTypes.enum ["aos-request-output-reference"];
      request = localKeyType;
      output = localKeyType;
    })
    // {
      check = value:
        builtins.isAttrs value
        && builtins.attrNames value == ["_type" "output" "request"]
        && value._type == "aos-request-output-reference"
        && localKeyType.check value.request
        && localKeyType.check value.output;
    };
in rec {
  ## Publishes the closed version-1 value bounds used by authoring and wire validation.
  limits = {
    maxSafeInteger = 9007199254740991;
    maxStringLength = 1048576;
    maxCollectionItems = 2000000;
    maxDocumentBytes = 32 * 1024 * 1024;
    maxStructuralDepth = 64;
    maxU32 = 4294967295;
  };

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
  in
    if normalized.kind == "boolean"
    then boolean
    else if normalized.kind == "integer"
    then integer {inherit (normalized) minimum maximum;}
    else if normalized.kind == "string"
    then
      string {
        maxLength = normalized.max_length;
        syntax = normalized.syntax;
      }
    else if normalized.kind == "string-enum"
    then enum normalized.values
    else if normalized.kind == "list"
    then
      list {
        element = fromSchema normalized.element;
        maxItems = normalized.max_items;
        unique = normalized.unique or false;
        canonicalOrder = normalized.canonical_order or false;
      }
    else if normalized.kind == "map"
    then
      map {
        keyMaxLength = normalized.key.max_length;
        keySyntax = normalized.key.syntax;
        maxEntries = normalized.max_entries;
        value = fromSchema normalized.value;
      }
    else if normalized.kind == "record"
    then
      record {
        fields = builtins.mapAttrs (_: fromSchema) normalized.fields;
        optional = normalized.optional_fields;
      }
    else if normalized.kind == "document-record"
    then
      documentRecord {
        keyMaxLength = normalized.key_max_length;
        fields = builtins.mapAttrs (_: fromSchema) normalized.fields;
        optional = normalized.optional_fields;
      }
    else if normalized.kind == "tagged-union"
    then
      decorate "decoded tagged union" normalized (moduleTypes.oneOf (builtins.attrValues (
        builtins.mapAttrs (_: fromSchema) normalized.variants
      )))
    else if normalized.kind == "disjoint-union"
    then disjointUnion (builtins.map fromSchema normalized.variants)
    else if normalized.kind == "optional"
    then optional (fromSchema normalized.value)
    else if normalized.kind == "artifact-reference"
    then artifactReference
    else if normalized.kind == "resource-reference"
    then resourceReference
    else if normalized.kind == "provider-assignment"
    then providerAssignment
    else operationResultReferenceType;

  boolean = decorate "boolean" schemas.boolean moduleTypes.bool;

  localKey =
    decorate "local key" (schemas.string {
      maxLength = 128;
      syntax = "local-key-v1";
    })
    localKeyType;

  packageName =
    decorate "package name" (schemas.string {
      maxLength = 128;
      syntax = null;
    })
    packageNameType;

  declarationKey =
    decorate "qualified declaration key" (schemas.string {
      maxLength = 257;
      syntax = null;
    })
    declarationKeyType;

  qualifiedName =
    decorate "qualified name" (schemas.string {
      maxLength = 128;
      syntax = "qualified-name-v1";
    })
    qualifiedNameType;

  digest =
    decorate "SHA-256 digest" (schemas.string {
      maxLength = 71;
      syntax = null;
    })
    digestType;

  stage =
    decorate "execution stage" (schemas.enum [
      "build"
      "initrd"
      "host"
      "system-container"
      "user"
      "application-container"
    ])
    stageType;

  valuePhase = enum [
    "evaluation"
    "artifact"
    "planning"
    "admission"
    "runtime"
    "observation"
  ];

  lifetime = decorate "resource lifetime" (schemas.enum [
    "attempt"
    "transaction"
    "instance"
    "persistent"
  ]) (moduleTypes.enum ["attempt" "transaction" "instance" "persistent"]);

  packageOutputSelector = packageOutputType;
  relativePath =
    decorate "relative path" (schemas.string {
      maxLength = 4096;
      syntax = null;
    })
    relativePathType;

  runtimeString = string {
    maxLength = 4096;
    syntax = null;
  };
  executionPath = let
    schema = schemas.string {
      maxLength = 4096;
      syntax = "execution-path-v1";
    };
    pathType = moduleTypes.addCheck moduleTypes.str isExecutionPath;
  in
    decorate "absolute execution path" schema pathType;
  principalName = decorate "principal name" localKey._abilitySchema localKeyType;
  groupName = decorate "group name" localKey._abilitySchema localKeyType;
  fileMode = let
    schema = schemas.string {
      maxLength = 4;
      syntax = null;
    };
  in
    decorate "file mode" schema (moduleTypes.addCheck moduleTypes.str (value:
        builtins.match "[0-7]{3,4}" value != null));
  capabilityName = let
    schema = schemas.string {
      maxLength = 128;
      syntax = null;
    };
  in
    decorate "Linux capability name" schema (moduleTypes.addCheck moduleTypes.str (value:
        builtins.match "CAP_[A-Z0-9_]+" value != null));

  interfaceKey = record {
    fields = {
      name = qualifiedName;
      abi = integer {
        minimum = 1;
        maximum = 4294967295;
      };
      descriptor = digest;
    };
  };

  environmentId = record {
    fields = {
      authority = localKey;
      key = localKey;
      stage = stage;
    };
  };

  instanceId = record {
    fields = {
      environment = environmentId;
      key = localKey;
    };
  };

  serviceId = record {
    fields = {
      instance = instanceId;
      service = localKey;
    };
  };

  integer = args: let
    schema = schemas.integer args;
    base =
      moduleTypes.addCheck moduleTypes.int (value:
        value >= schema.minimum && value <= schema.maximum);
  in
    decorate "integer" schema base;

  string = args: let
    schema = schemas.string args;
    base = moduleTypes.addCheck moduleTypes.str (value:
      builtins.stringLength value
      <= schema.max_length
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
    unique ? false,
    canonicalOrder ? false,
  }: let
    elementSchema = schemaOf "ability list element" element;
    schema = schemas.list {
      inherit maxItems unique canonicalOrder;
      element = elementSchema;
    };
    listType = moduleTypes.listOf element;
    checkedListType = moduleTypes.addCheck listType (value:
      builtins.length value
      <= schema.max_items
      && (let
        encoded = builtins.map builtins.toJSON value;
        distinct =
          builtins.length encoded
          == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (item: {
              name = item;
              value = true;
            })
            encoded)));
      in
        (!(schema.unique or false) || distinct)
        && (!(schema.canonical_order or false) || encoded == builtins.sort builtins.lessThan encoded)));
    normalize = value: let
      entries =
        builtins.map (item: {
          encoded = builtins.toJSON item;
          value = item;
        })
        value;
      ordered =
        if schema.canonical_order or false
        then builtins.sort (left: right: left.encoded < right.encoded) entries
        else entries;
    in
      (
        builtins.foldl' (
          state: entry:
            if (schema.unique or false) && builtins.hasAttr entry.encoded state.seen
            then state
            else {
              seen = state.seen // {${entry.encoded} = true;};
              values = state.values ++ [entry.value];
            }
        ) {
          seen = {};
          values = [];
        }
        ordered
      )
      .values;
    base =
      checkedListType
      // {
        merge = location: definitions:
          normalize (listType.merge location definitions);
      };
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
      builtins.stringLength key
      <= schema.key.max_length
      && syntaxMatches schema.key.syntax key;
    base = moduleTypes.addCheck (moduleTypes.attrsOf value) (entries:
      builtins.length (builtins.attrNames entries)
      <= schema.max_entries
      && builtins.all validKey (builtins.attrNames entries));
  in
    decorate "map" schema base;

  record = {
    fields,
    optional ? [],
  }: let
    normalizedFields = builtins.mapAttrs (name: value:
      normalizedField name (
        if builtins.elem name optional
        then
          if builtins.isAttrs value && value ? type
          then value // {optional = true;}
          else {
            type = value;
            optional = true;
          }
        else value
      ))
    fields;
    inferredOptional =
      builtins.filter
      (name: normalizedFields.${name}.optional)
      (builtins.attrNames normalizedFields);
    optionalFields = builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = true;
    }) (optional ++ inferredOptional)));
    schema = schemas.record {
      fields =
        builtins.mapAttrs
        (_: field: schemaOf "ability record field" field.fieldType)
        normalizedFields;
      optional = optionalFields;
    };
  in
    decorateRecord "record" "<lib.abilities.types.record>" schema normalizedFields optionalFields;

  documentRecord = {
    keyMaxLength,
    fields,
    optional ? [],
  }: let
    normalizedFields = builtins.mapAttrs (name: value:
      normalizedField name (
        if builtins.elem name optional
        then
          if builtins.isAttrs value && value ? type
          then value // {optional = true;}
          else {
            type = value;
            optional = true;
          }
        else value
      ))
    fields;
    inferredOptional = builtins.filter (
      name: normalizedFields.${name}.optional
    ) (builtins.attrNames normalizedFields);
    optionalFields = builtins.attrNames (builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = true;
    }) (optional ++ inferredOptional)));
    schema = schemas.documentRecord {
      inherit keyMaxLength;
      fields =
        builtins.mapAttrs (
          _: field: schemaOf "ability document-record field" field.fieldType
        )
        normalizedFields;
      optional = optionalFields;
    };
  in
    decorateRecord
    "document record"
    "<lib.abilities.types.document-record>"
    schema
    normalizedFields
    optionalFields;

  taggedUnion = {
    tag,
    variants,
  }: let
    variantSchemas =
      builtins.mapAttrs
      (name: variant: schemaOf "ability tagged-union variant '${name}'" variant)
      variants;
    schema = schemas.taggedUnion {
      inherit tag;
      variants = variantSchemas;
    };
    taggedType = moduleTypes.mkOptionType {
      name = "tagged ability union";
      description = "closed tagged ability union";
      check = value:
        builtins.isAttrs value
        && builtins.hasAttr tag value
        && builtins.hasAttr value.${tag} variants;
      merge = location: definitions: let
        value = (builtins.elemAt definitions (builtins.length definitions - 1)).value;
        variant =
          if builtins.isAttrs value && builtins.hasAttr tag value && builtins.hasAttr value.${tag} variants
          then variants.${value.${tag}}
          else throw "The option '${builtins.concatStringsSep "." location}' has an unknown tagged-union variant.";
      in
        variant.merge location definitions;
    };
  in
    decorate "tagged union" schema taggedType;

  disjointUnion = variants: let
    variantSchemas = builtins.map (schemaOf "ability disjoint-union variant") variants;
    schema = schemas.disjointUnion variantSchemas;
  in
    decorate "disjoint union" schema (moduleTypes.oneOf variants);

  optional = value: let
    schema = schemas.optional (schemaOf "optional ability value" value);
  in
    decorate "optional" schema (moduleTypes.nullOr value);

  refined = {
    name,
    description,
    type,
    predicate,
  }:
    type
    // {
      inherit name description;
      check = value: type.check value && predicate value;
      merge = location: definitions: let
        merged = type.merge location definitions;
      in
        if predicate merged
        then merged
        else throw "The option '${builtins.concatStringsSep "." location}' is not valid for ${description}.";
    };

  artifactReference = specialType "artifact-reference" schemas.artifactReference {
    _type = moduleTypes.enum ["aos-artifact-reference"];
    content = digestType;
    store_path = moduleTypes.str;
    nar_hash = digestType;
    closure = digestType;
  };
  resourceReference = specialType "resource-reference" schemas.resourceReference {
    _type = moduleTypes.enum ["aos-resource-reference"];
    interface = interfaceKeyType;
    resource = resourceIdType;
    operations = moduleTypes.listOf localKeyType;
    lifetime = moduleTypes.enum ["attempt" "transaction" "instance" "persistent"];
  };
  providerAssignment = specialType "provider-assignment" schemas.providerAssignment {
    provider = instanceType;
    interface = interfaceKeyType;
    implementation = strictRecordType "<lib.abilities.types.provider-implementation>" {
      descriptor = digestType;
      artifact = artifactReference;
      handler = moduleTypes.nullOr localKeyType;
    };
    incarnation = moduleTypes.str;
  };
  deferredResult = expectedType: let
    schema = schemaOf "deferred result" expectedType;
    admitsPathWithin =
      schema.kind == "string"
      && schema.syntax == "execution-path-v1";
    pathWithinType = moduleTypes.mkOptionType {
      name = "path within a deferred execution path";
      description = "normalized path below a literal or deferred absolute execution path";
      check = value:
        admitsPathWithin
        && builtins.isAttrs value
        && builtins.attrNames value == ["_type" "base" "relative_path"]
        && value._type == "aos-runtime-path"
        && relativePathType.check value.relative_path
        && (
          expectedType.check value.base
          || operationResultReferenceType.check value.base
          || pathWithinType.check value.base
        );
      merge = moduleTypes.mergeEqualOption;
    };
    authored = moduleTypes.mkOptionType {
      name = "literal or deferred expression";
      description = "literal value, exact operation result reference, or normalized child execution path";
      check = value:
        expectedType.check value
        || operationResultReferenceType.check value
        || pathWithinType.check value;
      merge = location: definitions: let
        value = (builtins.elemAt definitions (builtins.length definitions - 1)).value;
      in
        if builtins.isAttrs value && (value._type or null) == "aos-request-output-reference"
        then operationResultReferenceType.merge location definitions
        else if builtins.isAttrs value && (value._type or null) == "aos-runtime-path"
        then pathWithinType.merge location definitions
        else expectedType.merge location definitions;
    };
  in
    decorate "deferred result" schema authored;

  artifactSelector = decorate "symbolic artifact" schemas.artifactReference packageOutputType;

  executableReference = let
    argumentList = list {
      element = deferredResult runtimeString;
      maxItems = 128;
    };
    entryPoint = relativePath;
    schema = schemas.record {
      fields = {
        artifact = schemas.artifactReference;
        entry_point = schemaOf "executable entry point" entryPoint;
        arguments = schemaOf "executable arguments" argumentList;
      };
      optional = [];
    };
    authored = strictRecordType "<lib.abilities.types.executable-reference>" {
      artifact = artifactSelector;
      arguments = argumentList;
      entry_point = entryPoint;
    };
  in
    decorate "executable reference" schema authored;

  artifactPathReference = let
    path = relativePath;
    schema = schemas.record {
      fields = {
        artifact = schemas.artifactReference;
        path = schemaOf "artifact path" path;
      };
      optional = [];
    };
    authored = strictRecordType "<lib.abilities.types.artifact-path-reference>" {
      artifact = artifactSelector;
      inherit path;
    };
  in
    decorate "artifact path reference" schema authored;
}
