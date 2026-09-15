##! Constructors for symbolic systemd unit documents rendered by the provider binary.
{lib}: let
  markerPrefix = "@@AOS_SYSTEMD_SUBSTITUTION:";
  markerSuffix = "@@";

  mergeSubstitutions = left: right:
    builtins.foldl' (merged: key: let
      value = right.${key};
    in
      if builtins.hasAttr key merged && merged.${key} != value
      then throw "systemd semantic substitution digest collision"
      else merged // {${key} = value;})
    left
    (builtins.attrNames right);

  document = template: substitutions: {
    inherit template substitutions;
  };

  literal = value: let
    text = builtins.toString value;
  in
    if lib.hasInfix markerPrefix text
    then throw "literal systemd text contains the reserved substitution marker"
    else document text {};

  substitution = {
    prefix ? "",
    suffix ? "",
    encoding ? "raw",
    source,
  }: let
    value = {
      inherit encoding prefix source suffix;
    };
    key = "s-${builtins.hashString "sha256" (builtins.toJSON value)}";
  in
    document "${markerPrefix}${key}${markerSuffix}" {${key} = value;};

  concat = values:
    builtins.foldl' (combined: value: let
      selected =
        if builtins.isString value || builtins.isInt value
        then literal value
        else value;
    in {
      template = combined.template + selected.template;
      substitutions = mergeSubstitutions combined.substitutions selected.substitutions;
    })
    (document "" {})
    values;

  quotedLiteral = value:
    literal "\"${builtins.replaceStrings ["\\" "\"" "\n" "\r" "%"] ["\\\\" "\\\"" "\\n" "\\r" "%%"] (builtins.toString value)}\"";

  artifactPath = {
    artifact,
    relativePath,
    prefix ? "",
    suffix ? "",
    encoding ? "raw",
  }:
    substitution {
      inherit encoding prefix suffix;
      source = {
        kind = "artifact-path";
        inherit artifact;
        relative_path = relativePath;
      };
    };

  executionPath = {
    value,
    prefix ? "",
    suffix ? "",
    encoding ? "raw",
  }:
    substitution {
      inherit encoding prefix suffix;
      source = {
        kind = "execution-path";
        inherit value;
      };
    };

  groupName = {
    value,
    prefix ? "",
    suffix ? "",
    encoding ? "raw",
  }:
    substitution {
      inherit encoding prefix suffix;
      source = {
        kind = "group-name";
        inherit value;
      };
    };

  principalName = {
    value,
    prefix ? "",
    suffix ? "",
    encoding ? "raw",
  }:
    substitution {
      inherit encoding prefix suffix;
      source = {
        kind = "principal-name";
        inherit value;
      };
    };

  runtimeString = {
    value,
    prefix ? "",
    suffix ? "",
    encoding ? "raw",
  }:
    substitution {
      inherit encoding prefix suffix;
      source = {
        kind = "runtime-string";
        inherit value;
      };
    };

  systemdUnitName = {
    identity,
    prefix ? "",
    suffix ? "",
    encoding ? "raw",
  }:
    substitution {
      inherit encoding prefix suffix;
      source = {
        kind = "systemd-unit-name";
        inherit identity;
      };
    };

  directive = name: value: {
    inherit name;
    value =
      if builtins.isString value || builtins.isInt value
      then literal value
      else value;
  };

  section = name: directives: {
    inherit name directives;
  };
in {
  inherit
    artifactPath
    concat
    directive
    executionPath
    groupName
    literal
    principalName
    quotedLiteral
    runtimeString
    section
    substitution
    systemdUnitName
    ;
}
