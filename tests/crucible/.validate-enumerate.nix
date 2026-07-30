# Enumerates every derivation under checks.crucible.<phase>, tolerating
# eval-time throws so one red gate doesn't hide the rest. Emits JSON:
#   { ok = [ { path; drv; } ]; failed = [ { path; error = true; } ]; }
{phase}: let
  root = import ../../. {};
  isDrv = v: (v.type or "") == "derivation";
  walk = depth: path: v: let
    kind = builtins.tryEval (
      if isDrv v
      then "drv"
      else if builtins.isAttrs v
      then "set"
      else "other"
    );
  in
    if !kind.success
    then [
      {
        inherit path;
        error = true;
      }
    ]
    else if kind.value == "drv"
    then let
      d = builtins.tryEval v.drvPath;
    in
      if d.success
      then [
        {
          inherit path;
          drv = d.value;
        }
      ]
      else [
        {
          inherit path;
          error = true;
        }
      ]
    else if kind.value == "set"
    then
      if depth >= 5
      then [
        {
          inherit path;
          tooDeep = true;
        }
      ]
      else
        builtins.concatMap
        (name: walk (depth + 1) "${path}.${name}" v.${name})
        (builtins.attrNames v)
    else [];
  results = walk 0 "checks.crucible.${phase}" root.checks.crucible.${phase};
in {
  ok = builtins.filter (r: r ? drv) results;
  failed = builtins.filter (r: r ? error) results;
  tooDeep = builtins.filter (r: r ? tooDeep) results;
}
