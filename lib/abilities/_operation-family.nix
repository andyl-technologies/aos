##! lib/abilities/_operation-family.nix - Private operation-family normalizer.
##!
##! Interface methods and concrete effect operations share this closed semantic
##! vocabulary. Keeping one private normalizer prevents an interface from
##! advertising a family that the effect planner would later reject, without
##! adding an implementation helper to the public ability-authoring API.
{fail}: let
  requireAttrs = context: allowed: value: let
    unexpected =
      if builtins.isAttrs value
      then builtins.filter (name: !(builtins.elem name allowed)) (builtins.attrNames value)
      else [];
  in
    if !builtins.isAttrs value
    then fail "${context} must be an attribute set"
    else if unexpected != []
    then fail "${context} has unsupported fields: ${builtins.concatStringsSep ", " unexpected}"
    else value;

  requireChoice = context: choices: value:
    if builtins.elem value choices
    then value
    else fail "${context} is unsupported";
in
  value: let
    kind =
      if builtins.isAttrs value && builtins.isString (value.kind or null)
      then value.kind
      else fail "operation family must contain a string kind";
    simple = [
      "verify-artifact"
      "prepare-managed-configuration"
      "validate-candidate"
      "publish-configuration"
      "prepare-manager-configuration"
      "observe-readiness"
      "release-resource"
      "record-generation-association"
    ];
  in
    if builtins.elem kind simple
    then requireAttrs "operation family '${kind}'" ["kind"] value
    else if kind == "credential"
    then let
      checked = requireAttrs "credential operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "credential action" ["acquire" "deliver"] checked.action;}
    else if kind == "service-lifecycle"
    then let
      checked = requireAttrs "service lifecycle operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "service lifecycle action" ["start" "reload" "restart" "stop"] checked.action;}
    else if kind == "kubernetes-object"
    then let
      checked = requireAttrs "Kubernetes object operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "Kubernetes object action" ["apply" "delete" "observe"] checked.action;}
    else if kind == "network-endpoint"
    then let
      checked = requireAttrs "network endpoint operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "network endpoint action" ["materialize" "observe" "release"] checked.action;}
    else if kind == "host-storage"
    then let
      checked = requireAttrs "host storage operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "host storage action" ["ensure" "observe" "release"] checked.action;}
    else if kind == "host-network-policy"
    then let
      checked = requireAttrs "host network policy operation family" ["kind" "action"] value;
    in
      checked // {action = requireChoice "host network policy action" ["apply" "observe" "remove"] checked.action;}
    else fail "operation family '${kind}' is unsupported"
