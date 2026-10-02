##! Structural type merging and portable constraints used by deferred modules.
let
  lib = import ../../lib {system = "x86_64-linux";};
  project = import ../../lib/type-schema.nix {inherit lib;};
  evaluate = type: values:
    (lib.evalModules {
      inherit lib;
      modules = [{options.value = lib.mkOption {inherit type;};}] ++ builtins.map (value: {config.value = value;}) values;
    }).config.value;
  rejects = type: values: !(builtins.tryEval (builtins.deepSeq (evaluate type values) true)).success;
  variant = name:
    lib.types.submodule {
      _module.strict = true;
      options = {
        kind = lib.mkOption {type = lib.types.enum [name];};
        fields = lib.mkOption {
          type = lib.types.attrsOf lib.types.str;
          default = {};
        };
      };
    };
  union = lib.types.taggedUnion "kind" {
    first = variant "first";
    second = variant "second";
  };
  record = lib.types.submodule {
    options.source = lib.mkOption {type = lib.types.deferred lib.types.str;};
  };
  reference = {
    _type = "aos-effect-output";
    identity = ["scope" "producer" "operation" "instance"];
    output = "path";
    schema = project lib.types.str;
  };
  bounded = lib.types.strWith {
    maxLength = 4;
    pattern = "[0-7]{3,4}";
  };
  list = lib.types.listWith {
    elemType = lib.types.str;
    maxItems = 2;
    unique = true;
  };
  map = lib.types.attrsWith {
    elemType = lib.types.str;
    maxEntries = 1;
    keyMaxLength = 3;
    keySyntax = "local-key-v1";
  };
  boundedPolicy = lib.types.refined {
    type = lib.types.submodule {
      options = {
        allow = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
        };
        deny = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
        };
      };
    };
    constraints = [
      {
        kind = "disjoint-at";
        left = ["allow"];
        right = ["deny"];
      }
    ];
  };
  documented = lib.evalModules {
    inherit lib;
    modules = [
      {
        options.entries = lib.mkOption {
          type = lib.types.attrsOf (lib.types.submodule {
            options.command = lib.mkOption {type = lib.types.str;};
          });
          default = {};
        };
      }
      {
        options.entries = lib.mkOption {
          type = lib.types.attrsOf (lib.types.submodule {
            options.after = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
            };
          });
          default = {};
        };
      }
    ];
  };
  documentedEntries = builtins.head (builtins.filter (entry: entry.pathStr == "entries") documented._optionDecls);
in {
  booleanEnumPortable = assert (project (lib.types.enum [true]))
  == {
    kind = "refined";
    value.kind = "bool";
    constraints = [
      {
        kind = "boolean-value";
        value = true;
      }
    ];
  };
  assert (project (lib.types.enum [false true])).kind == "bool";
  assert evaluate (lib.types.enum [false]) [false] == false;
  assert rejects (lib.types.enum [false]) [true]; true;
  namedSubmoduleDocumentation = assert (project (lib.types.submodule ({name, ...}: {
    options.label = lib.mkOption {
      type = lib.types.str;
      default = name;
    };
  }))).fields.label.kind
  == "string"; true;
  canonicalEnumDocumentation = assert (project (lib.types.enum ["transaction" "instance" "persistent"])).values
  == [
    {value = "instance";}
    {value = "persistent";}
    {value = "transaction";}
  ]; true;
  mergedNestedDocumentation = assert builtins.attrNames documentedEntries.type.value.fields == ["after" "command"];
  assert documentedEntries.type.value.fields.after.element.kind == "string";
  assert !documentedEntries.type.value.open; true;
  constraintsAfterMerging = assert evaluate boundedPolicy [{allow = ["read"];} {deny = ["write"];}]
  == {
    allow = ["read"];
    deny = ["write"];
  };
  assert rejects boundedPolicy [{allow = ["read"];} {deny = ["read"];}]; true;
  portableRecordRefinement = assert (project boundedPolicy).kind == "refined";
  assert (project boundedPolicy).value.fields.allow.kind == "list"; true;
  jsonObjectsMerge = assert evaluate lib.types.json [{nested.first = "a";} {nested.second = [true null];}]
  == {
    nested = {
      first = "a";
      second = [true null];
    };
  }; true;
  jsonRejectsFunctions = assert !(lib.types.json.check (_: null)); true;
  selectedVariantMerges = assert evaluate union [
    {
      kind = "second";
      fields.a = "a";
    }
    {fields.b = "b";}
  ]
  == {
    kind = "second";
    fields = {
      a = "a";
      b = "b";
    };
  }; true;
  conflictingTags = assert rejects union [{kind = "first";} {kind = "second";}]; true;
  tagPriority = assert (evaluate union [{kind = lib.mkDefault "first";} {kind = "second";}]).kind == "second"; true;
  unknownTag = assert rejects union [{kind = "absent";}]; true;
  projectedVariant = assert (project union).variants.second.fields.kind.values == [{value = "second";}]; true;
  referenceDefaultIsAtomic = assert (evaluate record [(lib.mkDefault {source = reference;})]).source == reference; true;
  referenceCanBeOverridden = assert (evaluate record [(lib.mkDefault {source = reference;}) {source = "/replacement";}]).source == "/replacement"; true;
  bounds = assert evaluate bounded ["0755"] == "0755";
  assert rejects bounded ["00755"];
  assert rejects bounded ["0999"]; true;
  portablePattern = assert (project bounded).kind == "refined";
  assert (project bounded).value.max_length == 4; true;
  primitiveStringConstraints = let
    constraints = import ../../lib/types/constraints.nix;
    nonempty = (project lib.types.nonEmptyStr).constraints;
    singleLine = (project lib.types.singleLineStr).constraints;
  in
    assert evaluate lib.types.nonEmptyStr ["text"] == "text";
    assert rejects lib.types.nonEmptyStr [""];
    assert constraints.check nonempty "text" && !(constraints.check nonempty "");
    assert builtins.all (value:
      evaluate lib.types.singleLineStr [value] == value && constraints.check singleLine value)
    ["" "ordinary description" "tab\there" "carriage\rreturn"];
    assert rejects lib.types.singleLineStr ["two\nlines"];
    assert !(constraints.check singleLine "two\nlines"); true;
  unsupportedPattern = assert !(builtins.tryEval (builtins.deepSeq (project (lib.types.strMatching "(?=a)a")) true)).success; true;
  listMergeAndLimits = assert evaluate list [["a"] ["b"]] == ["a" "b"];
  assert rejects list [["a"] ["a"]];
  assert rejects list [["a" "b" "c"]]; true;
  mapMergeAndLimits = assert evaluate map [{key = "a";}] == {key = "a";};
  assert rejects map [
    {
      a = "a";
      b = "b";
    }
  ];
  assert rejects map [{long = "x";}];
  assert rejects map [{"a b" = "x";}]; true;
  portableIntegerBounds = assert (project (lib.types.ints.between 1 3)).min == 1;
  assert rejects (lib.types.ints.between 1 3) [0]; true;
}
