##! Converts typed module values to portable deferred value expressions.
{requestIdFor}: let
  isDeferred = value:
    if builtins.isAttrs value
    then
      builtins.elem (value._type or null) [
        "aos-request-output-reference"
        "aos-runtime-path"
        "aos-canonical-json"
        "aos-resource-reference"
        "aos-artifact-reference"
      ]
      || builtins.any isDeferred (builtins.attrValues value)
    else if builtins.isList value
    then builtins.any isDeferred value
    else false;

  expression = value: let
    marker =
      if builtins.isAttrs value
      then value._type or null
      else null;
  in
    if marker == "aos-request-output-reference"
    then {
      source = "request-output";
      reference = {
        request = requestIdFor value.request;
        output = value.output;
      };
    }
    else if marker == "aos-runtime-path"
    then {
      source = "path-within";
      base = expression value.base;
      inherit (value) relative_path;
    }
    else if marker == "aos-canonical-json"
    then {
      source = "canonical-json";
      inherit (value) source_schema max_bytes;
      value = expression value.value;
    }
    else if marker == "aos-resource-reference"
    then {
      source = "resource-reference";
      reference = builtins.removeAttrs value ["_type"];
    }
    else if marker == "aos-artifact-reference"
    then {
      source = "artifact-reference";
      reference = builtins.removeAttrs value ["_type"];
    }
    else if isDeferred value && builtins.isList value
    then {
      source = "list";
      items = builtins.map expression value;
    }
    else if isDeferred value && builtins.isAttrs value
    then {
      source = "object";
      fields = builtins.mapAttrs (_: expression) value;
    }
    else {
      source = "literal";
      inherit value;
    };
in
  expression
