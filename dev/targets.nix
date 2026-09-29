{
  category,
  scope ? "",
}: let
  aos = import ../. {};
  names = builtins.attrNames;
  join = builtins.concatStringsSep "\n";
  isDerivation = value: builtins.isAttrs value && (value.type or null) == "derivation";
  collectChecks = prefix: value: let
      kind = builtins.tryEval (value.type or null);
      children = builtins.tryEval (names value);
    in
      if kind.success && kind.value == "derivation"
      then [prefix]
      else if children.success
      then builtins.concatMap (name: collectChecks "${prefix}.${name}" value.${name}) children.value
      else [];
  checkNames = builtins.concatMap (
    group: let
      value = aos.checks.${group};
      kind = builtins.tryEval (value.type or null);
      children = builtins.tryEval (names value);
    in
      if group == "terrane"
      then collectChecks group value
      else if kind.success && kind.value == "derivation"
      then [group]
      else if children.success
      then map (name: "${group}.${name}") children.value
      else [group]
  ) (names aos.checks);
  imageNames = builtins.concatMap (
    variant:
      if aos.systems.${variant}.build ? image
      then map (format: "${variant}:${format}") (names aos.systems.${variant}.build.image)
      else []
  ) (names aos.systems);
  containerNames = builtins.concatMap (
    variant:
      map (kind: "${variant}:${kind}") [
        "oci"
        "docker"
        "metadata"
      ]
  ) (names aos.containerImages ++ ["aos-testing"]);
  buildNames = builtins.concatMap (
    variant:
      map (name: "${variant}:${name}") (
        builtins.filter (
          name: let
            checked = builtins.tryEval aos.systems.${variant}.build.${name};
          in
            checked.success && isDerivation checked.value
        ) (names aos.systems.${variant}.build)
      )
  ) (names aos.systems);
  values = {
    packages = aos.pkgs.packageNames;
    images = imageNames;
    containers = containerNames;
    checks =
      if scope == ""
      then checkNames
      else let
        target =
          builtins.foldl' (attrs: name:
            if attrs != null && builtins.isAttrs attrs && builtins.hasAttr name attrs
            then builtins.getAttr name attrs
            else null)
          aos.checks (
            builtins.filter builtins.isString (builtins.split "\\." scope)
          );
      in
        if target == null
        then []
        else if isDerivation target
        then [scope]
        else collectChecks scope target;
    builds = buildNames;
    evals = [
      "eval"
      "eval-standalone"
    ];
  };
in
  join values.${category}
