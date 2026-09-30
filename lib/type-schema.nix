##! Projects native module option types into the shared portable type algebra.
{lib}: let
  optionTree = options:
    builtins.mapAttrs (_: option:
      if option ? type
      then project option.type
      else {
        kind = "submodule";
        open = false;
        fields = optionTree option;
      })
    (builtins.removeAttrs options ["_module"]);

  project = type: let
    schema = type._aosDocType or (throw "Option type '${type.description}' has no portable schema.");
  in
    if !(type._portable or true)
    then throw "Option type '${type.description}' uses a Nix predicate that cannot validate deferred runtime values."
    else if type ? _refinementConstraints
    then {
      kind = "refined";
      value = project (builtins.removeAttrs type ["_refinementConstraints"]);
      constraints = type._refinementConstraints;
    }
    else if type ? _projectionType
    then project type._projectionType
    else if type ? _variantTypes
    then schema // {variants = builtins.mapAttrs (_: project) type._variantTypes;}
    else if type ? _alternativeTypes
    then schema // {alternatives = builtins.map project type._alternativeTypes;}
    else if type ? _submodule
    then {
      kind = "submodule";
      open = false;
      fields = optionTree (lib.submoduleOptions type []);
    }
    else if type._deferred or false
    then project type._nestedType
    else if type ? _elementType
    then schema // {value = project type._elementType;}
    else if type ? _nestedType
    then
      schema
      // {
        ${
          if schema.kind == "list"
          then "element"
          else "value"
        } =
          project type._nestedType;
      }
    else if schema.kind == "string" && (schema.pattern or null) != null
    then {
      kind = "refined";
      value = schema // {pattern = null;};
      constraints = [
        {
          kind = "string-pattern";
          pattern = (import ./types/portable-pattern.nix) schema.pattern;
        }
      ];
    }
    else if schema.kind == "opaque"
    then throw "Option type '${type.description}' cannot cross the activation boundary."
    else schema;
in
  project
