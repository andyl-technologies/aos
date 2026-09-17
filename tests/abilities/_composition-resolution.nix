##! Carries selected compose-generated requests into a complete evaluation round.
{
  abilities,
  requestKeys ? builtins.attrNames abilities.compositionPendingRequests,
}: let
  pendingFor = requestKey:
    abilities.compositionPendingRequests.${requestKey}
    or (throw "composition resolution fixture has no pending request '${requestKey}'");
in {
  requests = builtins.listToAttrs (builtins.map (requestKey: {
      name = requestKey;
      value = (pendingFor requestKey).declaration;
    })
    requestKeys);
  requirements = builtins.listToAttrs (builtins.map (requestKey: let
      pending = pendingFor requestKey;
      requirementKey = pending.declaration.requirement;
    in {
      name = requirementKey;
      value = abilities.compositionRequirements.${requirementKey};
    })
    requestKeys);
}
