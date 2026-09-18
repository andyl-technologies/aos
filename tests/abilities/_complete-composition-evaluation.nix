##! Re-evaluates a pre-bound composition fixture until every child is resolved.
{
  evaluate,
  maxRounds ? 16,
}: let
  emptyResolution = {
    requests = {};
    requirements = {};
  };
  resolve = round: abilityResolution: let
    evaluation = evaluate abilityResolution;
    abilities = evaluation.config.aos.abilities;
    pending = abilities.compositionPendingRequests;
    additions = import ./_composition-resolution.nix {inherit abilities;};
    nextResolution = {
      requests = abilityResolution.requests // additions.requests;
      requirements = abilityResolution.requirements // additions.requirements;
    };
  in
    if pending == {}
    then evaluation
    else if round >= maxRounds
    then throw "composition fixture did not converge within ${toString maxRounds} complete evaluations"
    else if nextResolution == abilityResolution
    then throw "composition fixture has pending requests but produced no new resolution inputs"
    else resolve (round + 1) nextResolution;
in
  resolve 0 emptyResolution
