# Keeps all approved measured outputs as real Nix store references.
{
  comparisonFile,
  approvedSha256,
}: let
  approved =
    if approvedSha256 == null
    then null
    else if comparisonFile == null || builtins.match "[0-9a-f]{64}" approvedSha256 == null
    then throw "campaign performance comparison approval is invalid"
    else if builtins.hashFile "sha256" comparisonFile != approvedSha256
    then throw "campaign performance comparison hash mismatch"
    else builtins.fromJSON (builtins.readFile comparisonFile);
  pairs = approved.pairs or [];
  outputs = builtins.concatMap (pair: [pair.reference.output pair.candidate.output]) pairs;
  validRoot = output:
    builtins.isString output
    && builtins.match "/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+" output != null;
  unique = builtins.attrNames (builtins.listToAttrs (map (output: {
      name = output;
      value = true;
    })
    outputs));
in
  if approved == null
  then []
  else if
    approved.schema
    != "crucible.campaign-performance.comparison.v2"
    || builtins.length pairs != 8
    || !(builtins.all validRoot outputs)
    || builtins.length unique != 16
  then throw "campaign performance requires sixteen distinct whole approved sample roots"
  # JSON strings carry no path context. Reattach authenticated whole-root
  # custody before sandbox execution and keep it in the resulting evidence.
  else map builtins.storePath outputs
